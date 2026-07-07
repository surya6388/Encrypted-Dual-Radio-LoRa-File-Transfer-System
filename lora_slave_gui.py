"""
LoRa Slave Monitor GUI (receiver side)
---------------------------------------
Connects to the SLAVE's serial port (a *second* USB port from the master's)
and:
  - Watches the slave's serial output for transfer status lines
  - Reassembles RXFILE_START:<len> / <raw bytes> / RXFILE_END, which is
    RAW BINARY DATA (already AES-128-GCM decrypted + verified on-device,
    or best-effort decrypted if the transfer was PARTIAL) -- read
    byte-by-byte, not line-by-line, since it can contain any byte value.
  - Reads the RXMETA:<type>:<filename>:<len> line the firmware sends
    right before RXFILE_START, so it knows whether the payload is an
    image, PDF, DOCX, plain text, or something else, and what to name
    it on save.
  - AUTO-SAVES every completed (or partially-recovered) file transfer
    to a "received_files" folder next to this script, using the
    sender's original filename (which already has the correct
    extension) whenever it's available -- so a PDF sent from the other
    side arrives as an actual openable .pdf here, an image as an actual
    .png/.jpg you can open in any viewer, an .xlsx as an actual
    spreadsheet, and so on. A manual "Save As..." is still available if
    you want a copy somewhere else. Plain text messages are shown
    inline, not saved as files.
  - Shows RXDONE (full success), RXPARTIAL (best-effort partial
    recovery -- some chunks never arrived, image/file may have gaps or
    artifacts but you get *something* instead of nothing), RXCRYPTOFAIL
    (auth tag invalid -- wrong key/corruption/tampering), and RXFAILED
    (no chunks arrived at all before timeout).

  ------------------------------------------------------------------
  FIX IN THIS VERSION: correct fallback type when metadata is missing
  ------------------------------------------------------------------
  If a file payload somehow arrives with no preceding RXMETA line (e.g.
  log lines got out of sync), the old fallback was:

      ftype, fname = self.pending_meta if self.pending_meta else (5, "")

  ...where 5 = PPTX. That silently mislabeled unknown files as
  PowerPoint presentations. It's now (6, "") = OTHER, which is the
  honest "we don't know what this is" answer and will save with a
  .bin extension plus a timestamped name instead of a wrong extension.

  This is a rare fallback path -- with the master firmware's new
  multi-pass retry, RXMETA (which comes from chunk 0) should now
  reliably arrive alongside every completed or partially-recovered
  transfer.
  ------------------------------------------------------------------

Install deps:
    pip install pyserial pillow --break-system-packages

Run:
    python lora_slave_gui.py
"""

import io
import os
import threading
import time

import serial
import serial.tools.list_ports
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

FTYPE_NAMES = {0: "TEXT", 1: "PNG", 2: "JPG", 3: "PDF", 4: "DOCX", 5: "PPTX", 6: "OTHER"}
FTYPE_EXT = {0: ".txt", 1: ".png", 2: ".jpg", 3: ".pdf", 4: ".docx", 5: ".pptx", 6: ".bin"}


class SlaveReader:
    """
    Byte-oriented protocol reader for the slave's serial stream.

    Ordinary lines (STATUS, [RX] chunk N/M ..., RXDONE:..., RXPARTIAL:...,
    RXMETA:..., RXCRYPTOFAIL:..., RXFAILED:..., [CRYPTO]..., etc.) are
    '\n'-terminated text.

    A file payload is framed as:
        b"RXFILE_START:<decimal length>\\n"
        <exactly <length> raw bytes, may contain any byte value>
        b"\\n"
        b"RXFILE_END\\n"
    and is normally preceded by an RXMETA: line (ordinary text) telling
    us the file type/name -- captured separately, not part of the framing.

    on_line(str)   -- called for each ordinary text line
    on_file(bytes) -- called with the fully reassembled raw payload
    """

    def __init__(self, on_line, on_file):
        self.on_line = on_line
        self.on_file = on_file
        self._buf = bytearray()
        self._mode = "TEXT"          # TEXT | CAPTURE | CAPTURE_TRAILER | CAPTURE_TRAILER_LINE
        self._expect_len = 0
        self._payload = bytearray()

    def feed(self, data: bytes):
        self._buf.extend(data)
        self._pump()

    def _pump(self):
        progressed = True
        while progressed:
            progressed = False

            if self._mode == "TEXT":
                nl = self._buf.find(b"\n")
                if nl == -1:
                    break
                line = bytes(self._buf[:nl])
                del self._buf[:nl + 1]
                progressed = True

                text = line.decode(errors="replace").strip("\r").strip()
                if text.startswith("RXFILE_START:"):
                    try:
                        self._expect_len = int(text.split(":", 1)[1])
                    except ValueError:
                        self._expect_len = 0
                    self._payload = bytearray()
                    self._mode = "CAPTURE"
                elif text:
                    self.on_line(text)

            elif self._mode == "CAPTURE":
                need = self._expect_len - len(self._payload)
                take = min(need, len(self._buf))
                if take > 0:
                    self._payload.extend(self._buf[:take])
                    del self._buf[:take]
                    progressed = True
                if len(self._payload) >= self._expect_len:
                    self._mode = "CAPTURE_TRAILER"
                    progressed = True

            elif self._mode == "CAPTURE_TRAILER":
                # firmware's separating println() -- discard whatever it is
                sep_nl = self._buf.find(b"\n")
                if sep_nl == -1:
                    break
                del self._buf[:sep_nl + 1]
                progressed = True
                self._mode = "CAPTURE_TRAILER_LINE"

            elif self._mode == "CAPTURE_TRAILER_LINE":
                trailer_nl = self._buf.find(b"\n")
                if trailer_nl == -1:
                    break
                trailer = bytes(self._buf[:trailer_nl]).decode(errors="replace").strip("\r").strip()
                del self._buf[:trailer_nl + 1]
                progressed = True
                if trailer == "RXFILE_END":
                    self.on_file(bytes(self._payload))
                else:
                    self.on_line("[WARN] Expected RXFILE_END, got: " + trailer)
                self._mode = "TEXT"


class SlaveGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("LoRa Slave Monitor (decrypt + auto-save)")
        self.root.geometry("780x760")

        self.save_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "received_files")
        os.makedirs(self.save_dir, exist_ok=True)

        self.ser = None
        self.reader_thread = None
        self.stop_reader = False
        self.reader = SlaveReader(self._on_line_threadsafe, self._on_file_threadsafe)

        self.last_payload_bytes = None
        self.last_photo = None  # keep a reference so Tk doesn't GC it
        self.pending_meta = None  # (ftype_int, filename) from the most recent RXMETA line
        self.last_ftype_name = "OTHER"
        self.last_fname = ""
        self.last_saved_path = None

        self._build_ui()
        self._refresh_ports()

    # ---------------- UI ----------------

    def _build_ui(self):
        pad = {"padx": 8, "pady": 6}

        conn = ttk.LabelFrame(self.root, text="Connection (Slave's COM port)")
        conn.pack(fill="x", **pad)

        ttk.Label(conn, text="Port:").grid(row=0, column=0, padx=4, pady=4)
        self.port_var = tk.StringVar()
        self.port_combo = ttk.Combobox(conn, textvariable=self.port_var, width=20)
        self.port_combo.grid(row=0, column=1, padx=4, pady=4)

        ttk.Button(conn, text="Refresh", command=self._refresh_ports).grid(row=0, column=2, padx=4)
        ttk.Button(conn, text="Connect", command=self._connect).grid(row=0, column=3, padx=4)
        ttk.Button(conn, text="Disconnect", command=self._disconnect).grid(row=0, column=4, padx=4)

        self.conn_status = ttk.Label(conn, text="Disconnected", foreground="red")
        self.conn_status.grid(row=0, column=5, padx=8)

        if not PIL_AVAILABLE:
            ttk.Label(conn, text="⚠ Pillow not installed -- image preview disabled "
                                  "(pip install pillow --break-system-packages)",
                      foreground="#b33").grid(row=1, column=0, columnspan=6, sticky="w", padx=4)

        ttk.Label(conn, text=f"📁 Received files auto-save to: {self.save_dir}",
                  foreground="#555", font=("", 8)).grid(row=2, column=0, columnspan=5, sticky="w", padx=4)
        ttk.Button(conn, text="Open Folder", command=self._open_save_folder).grid(row=2, column=5, padx=4)

        # --- status frame ---
        status_frame = ttk.LabelFrame(self.root, text="Last Transfer")
        status_frame.pack(fill="x", **pad)

        self.transfer_status = ttk.Label(status_frame, text="Waiting for transfer...", font=("", 11, "bold"))
        self.transfer_status.pack(anchor="w", padx=8, pady=(6, 0))

        self.transfer_detail = ttk.Label(status_frame, text="")
        self.transfer_detail.pack(anchor="w", padx=8, pady=(0, 6))

        # --- preview frame ---
        img_frame = ttk.LabelFrame(self.root, text="Decrypted Payload Preview")
        img_frame.pack(fill="x", **pad)

        self.image_label = ttk.Label(img_frame, text="(nothing received yet)", anchor="center")
        self.image_label.pack(padx=8, pady=8)

        btns = ttk.Frame(img_frame)
        btns.pack(pady=(0, 8))
        self.save_btn = ttk.Button(btns, text="Save a Copy As...", command=self._save_payload, state="disabled")
        self.save_btn.pack(side="left", padx=4)
        ttk.Label(img_frame, text="(files auto-save to the received_files folder above; use this only for an extra copy)",
                  foreground="#777", font=("", 8)).pack(pady=(0, 4))

        # --- text message frame ---
        msg_frame = ttk.LabelFrame(self.root, text="Received Text Message")
        msg_frame.pack(fill="x", **pad)
        self.text_message_var = tk.StringVar(value="(none yet)")
        ttk.Label(msg_frame, textvariable=self.text_message_var, wraplength=740,
                  justify="left", font=("", 10)).pack(anchor="w", padx=8, pady=6)

        # --- log frame ---
        log_frame = ttk.LabelFrame(self.root, text="Serial Log (Slave)")
        log_frame.pack(fill="both", expand=True, **pad)

        self.log_text = tk.Text(log_frame, height=16, wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=4, pady=4)
        scrollbar = ttk.Scrollbar(self.log_text, command=self.log_text.yview)
        self.log_text.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

    # ---------------- Serial handling ----------------

    def _refresh_ports(self):
        ports = [p.device for p in serial.tools.list_ports.comports()]
        current = self.port_var.get()
        self.port_combo["values"] = ports
        if not ports:
            self._log("[GUI] Refresh: no serial ports found.")
            self.port_var.set("")
            return
        self._log(f"[GUI] Refresh: found {len(ports)} port(s): {', '.join(ports)}")
        if current not in ports:
            self.port_var.set(ports[0])

    def _connect(self):
        port = self.port_var.get()
        if not port:
            messagebox.showwarning("No port", "Select a serial port first.")
            return
        try:
            # Same fix as the sender GUI: opening a pyserial port normally
            # toggles DTR/RTS, which resets most ESP32 dev boards on every
            # connect. Holding both low before open() avoids that.
            self.ser = serial.Serial()
            self.ser.port = port
            self.ser.baudrate = 115200
            self.ser.timeout = 0.2
            self.ser.dtr = False
            self.ser.rts = False
            self.ser.open()
            self.conn_status.config(text=f"Connected ({port})", foreground="green")
            self.stop_reader = False
            self.reader_thread = threading.Thread(target=self._read_loop, daemon=True)
            self.reader_thread.start()
            self._log(f"Connected to {port} (DTR/RTS held low -- board should NOT auto-reset)")
        except Exception as e:
            messagebox.showerror("Connection failed", str(e))

    def _disconnect(self):
        self.stop_reader = True
        if self.ser and self.ser.is_open:
            self.ser.close()
        self.conn_status.config(text="Disconnected", foreground="red")
        self._log("Disconnected")

    def _read_loop(self):
        while not self.stop_reader and self.ser and self.ser.is_open:
            try:
                chunk = self.ser.read(512)
                if chunk:
                    self.reader.feed(chunk)
            except Exception as e:
                self._log(f"[ERROR] Read error: {e}")
                break

    def _on_line_threadsafe(self, text):
        self.root.after(0, self._handle_line, text)

    def _on_file_threadsafe(self, payload: bytes):
        self.root.after(0, self._handle_file, payload)

    # ---------------- line/event handling ----------------

    def _handle_line(self, line):
        self._log(line)

        if line.startswith("RXMETA:"):
            # RXMETA:<typeInt>:<filename>:<dataLen>
            try:
                parts = line.split(":", 3)
                ftype = int(parts[1])
                fname = parts[2]
                self.pending_meta = (ftype, fname)
            except Exception:
                self.pending_meta = None

        elif line.startswith("RXDONE:"):
            # RXDONE:<receivedCount>:<totalChunks>:<elapsedSec>:<rssi>:<distanceM>
            try:
                _, recv, total, elapsed, rssi, dist = line.split(":")
                self.transfer_status.config(text="✅ Received + Decrypted OK", foreground="#2a7")
                self.transfer_detail.config(
                    text=f"{recv}/{total} chunks  |  {float(elapsed):.2f}s  |  RSSI {rssi}  |  ~{float(dist):.1f}m")
            except Exception:
                pass

        elif line.startswith("RXPARTIAL:"):
            try:
                _, recv, total, elapsed, rssi, dist = line.split(":")
                pct = int(100 * int(recv) / max(1, int(total)))
                self.transfer_status.config(text=f"⚠ Partial recovery ({pct}% of chunks)", foreground="#c80")
                self.transfer_detail.config(
                    text=f"{recv}/{total} chunks arrived, transfer stalled. Best-effort decrypt "
                         f"used -- file may have gaps/artifacts but isn't discarded. "
                         f"{float(elapsed):.2f}s | RSSI {rssi} | ~{float(dist):.1f}m")
            except Exception:
                pass

        elif line.startswith("RXCRYPTOFAIL:"):
            self.transfer_status.config(text="❌ DECRYPT FAIL (GCM auth tag invalid)", foreground="#b33")
            self.transfer_detail.config(text="Data arrived but failed authentication -- "
                                              "wrong key, corruption, or tampering. Payload discarded.")
            self._clear_payload()

        elif line.startswith("RXFAILED:"):
            try:
                _, got, total = line.split(":")
                self.transfer_status.config(text="⚠ No usable data", foreground="#c80")
                self.transfer_detail.config(text=f"Only {got}/{total} chunks arrived -- too little to recover anything.")
            except Exception:
                pass
            self._clear_payload()

        elif line.startswith("[RX] chunk"):
            self.transfer_status.config(text="Receiving...", foreground="#333")
            self.transfer_detail.config(text=line.replace("[RX] chunk ", ""))

        elif line.startswith("[RX] WARNING: chunk 0"):
            # Surfaced by the firmware when metadata (type/filename) is
            # suspect -- e.g. chunk 0 never arrived even in a best-effort
            # partial recovery. Flag it plainly rather than silently
            # trusting whatever garbage RXMETA carries.
            self.transfer_status.config(text="⚠ Metadata unreliable (chunk 0 missing)", foreground="#c80")

    def _unique_path(self, filename: str) -> str:
        """Avoid clobbering an earlier received file with the same name."""
        base, ext = os.path.splitext(filename)
        candidate = os.path.join(self.save_dir, filename)
        n = 1
        while os.path.exists(candidate):
            candidate = os.path.join(self.save_dir, f"{base}_{n}{ext}")
            n += 1
        return candidate

    def _open_save_folder(self):
        import subprocess, sys
        try:
            if sys.platform.startswith("win"):
                os.startfile(self.save_dir)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", self.save_dir])
            else:
                subprocess.Popen(["xdg-open", self.save_dir])
        except Exception as e:
            messagebox.showinfo("Folder location", f"Received files are saved to:\n{self.save_dir}\n\n({e})")

    def _handle_file(self, payload: bytes):
        self.last_payload_bytes = payload

        # FIX: fallback used to be (5, "") = PPTX, which silently
        # mislabeled any file that arrived without a preceding RXMETA
        # line as a PowerPoint file. Now falls back to (6, "") = OTHER,
        # the honest "type unknown" answer -- this only matters in the
        # rare case where the RXMETA line itself never showed up.
        ftype, fname = self.pending_meta if self.pending_meta else (6, "")
        self.pending_meta = None
        ftype_name = FTYPE_NAMES.get(ftype, "OTHER")
        self.last_ftype_name = ftype_name
        self.last_fname = fname
        self.last_saved_path = None

        self._log(f"[GUI] Captured {len(payload)} raw decrypted bytes (type={ftype_name}, name={fname!r})")
        self.save_btn.config(state="normal")
        self.text_message_var.set("(none yet)")

        # ---- TEXT: show inline, never written to disk as a "file" ----
        if ftype_name == "TEXT":
            try:
                text = payload.decode("utf-8")
                self.text_message_var.set(text)
                self.image_label.config(image="", text=f"(text message shown below -- {len(payload)} bytes)")
                self._log(f"[GUI] Received text message: {text!r}")
                return
            except UnicodeDecodeError:
                self._log("[GUI] RXMETA said TEXT but payload isn't valid UTF-8 -- saving as a file instead")
                ftype_name = "OTHER"
                self.last_ftype_name = ftype_name

        # ---- Everything else: reconstruct the real file on disk right away ----
        ext = FTYPE_EXT.get(ftype, ".bin")
        if fname.strip() and "." in fname:
            # Prefer the sender's original filename (already has the right
            # extension) when we have one.
            safe_name = os.path.basename(fname.strip())
        else:
            safe_name = f"received_{time.strftime('%Y%m%d_%H%M%S')}{ext}"

        save_path = self._unique_path(safe_name)
        try:
            with open(save_path, "wb") as f:
                f.write(payload)
            self.last_saved_path = save_path
            self._log(f"[GUI] Auto-saved -> {save_path}")
        except Exception as e:
            self._log(f"[GUI] Auto-save FAILED: {e}")

        # Preview images inline; everything else just reports where it landed.
        if ftype_name in ("PNG", "JPG") and PIL_AVAILABLE:
            try:
                img = Image.open(io.BytesIO(payload))
                img.load()
                self._show_image(img)
                if self.last_saved_path:
                    self.transfer_detail.config(
                        text=self.transfer_detail.cget("text") + f"  |  saved: {os.path.basename(save_path)}")
                return
            except Exception:
                self.image_label.config(
                    image="", text=f"(Expected an image but couldn't decode it -- likely a partial/"
                                   f"corrupted transfer. Raw bytes still saved to:\n{save_path})")
                return

        where = f"\nSaved to: {save_path}" if self.last_saved_path else "\n(auto-save failed, use Save As...)"
        self.image_label.config(
            image="", text=f"{ftype_name} file received: {os.path.basename(save_path)}  "
                            f"({len(payload)} bytes){where}")

    def _show_image(self, img):
        display_img = img.copy()
        target = 320
        longest = max(display_img.size)
        if longest != target:
            scale = target / longest
            new_size = (max(1, int(display_img.width * scale)), max(1, int(display_img.height * scale)))
            display_img = display_img.resize(new_size, Image.LANCZOS)

        self.last_photo = ImageTk.PhotoImage(display_img)
        self.image_label.config(image=self.last_photo, text="")
        self._log(f"[GUI] Decoded image: {img.size[0]}x{img.size[1]} mode={img.mode}")

    def _clear_payload(self):
        self.last_payload_bytes = None
        self.last_photo = None
        self.pending_meta = None
        self.last_ftype_name = "OTHER"
        self.last_fname = ""
        self.last_saved_path = None
        self.image_label.config(image="", text="(no data)")
        self.save_btn.config(state="disabled")
        self.text_message_var.set("(none yet)")

    def _log(self, msg):
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")

    # ---------------- save actions ----------------

    def _save_payload(self):
        if not self.last_payload_bytes:
            return
        if self.last_saved_path:
            suggested_name = os.path.basename(self.last_saved_path)
        else:
            suggested_name = self.last_fname.strip()
        if not suggested_name:
            ext = FTYPE_EXT.get(
                next((k for k, v in FTYPE_NAMES.items() if v == self.last_ftype_name), 6), ".bin")
            suggested_name = f"received{ext}"
        path = filedialog.asksaveasfilename(
            initialfile=suggested_name,
            filetypes=[("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(self.last_payload_bytes)
            self._log(f"[GUI] Saved a copy: {len(self.last_payload_bytes)} bytes to {path}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = SlaveGUI(root)
    root.mainloop()
