"""
LoRa Test GUI (sender / master side)
-------------------------------------
Connects to the MASTER's serial port (USB) and lets you:
  - Send a plain text message to a node
  - Send an image (with resize+JPEG, OR an exact lossless PNG passthrough),
    or any other file (PDF, DOCX, XLSX, etc.) as raw bytes
  - Watch live progress: chunk N/total, success/fail, elapsed time

  ---------------------------------------------------------------
  PROTOCOL NOTE (must match LoRa_Master.ino)
  ---------------------------------------------------------------
  SENDFILE command is now:
      SENDFILE:<nodeHex>:<byteCount>:<TYPE>:<filename>\n
      <raw bytes>
  TYPE is one of TEXT, PNG, JPG, PDF, DOCX, PPTX, OTHER -- the firmware
  uses this (plus filename) to build a small metadata header that gets
  encrypted along with your data, so the receiver knows what it got.
  Note: the TYPE string only affects the type BYTE sent to the
  firmware; the real filename (with its real extension, e.g. ".xlsx")
  is always sent as-is, so the receiver can reconstruct the correct
  file even for types that map to "OTHER".

  This GUI still sends RAW, UNENCRYPTED bytes to the master over USB
  serial -- the master encrypts everything with AES-128-GCM before it
  goes out over LoRa, so the key never touches the PC/USB link.
  ---------------------------------------------------------------

  ---------------------------------------------------------------
  IMAGE FIDELITY: LOSSLESS vs COMPRESSED
  ---------------------------------------------------------------
  - "Exact / Lossless" sends the original file bytes completely
    untouched (no resize, no recompression) -- what arrives is
    byte-for-byte identical to what you selected, colors included.
    This costs more airtime/chunks and is best for smaller images
    or when running over the SX1278 raw-binary path.
  - "Compressed" resizes and re-encodes as JPEG (adjustable quality)
    or PNG, trading some fidelity for a much smaller transfer -- use
    this for larger photos where an exact copy would take too long
    or exceed the chunk ceiling.
  - Non-image files (PDF, DOCX, XLSX, etc.) are ALWAYS sent byte-exact
    regardless of this setting -- the fidelity controls only apply to
    images, since there's no meaningful "resize" for a spreadsheet or
    document.
  ---------------------------------------------------------------

  LoRa airtime is small, so every byte costs real transfer time and
  retry risk. The slave firmware has MAX_CHUNKS 4200 (see
  LoRa_Slave.ino). This GUI estimates chunk count for both radios and
  warns before sending if it would be close to or exceed that ceiling.

  The master firmware now does multi-pass selective retry, so a single
  bad chunk (including the metadata-carrying first chunk) no longer
  aborts the whole transfer -- larger raw files like PDFs/DOCX/XLSX
  should complete reliably now, just taking longer for more chunks.

Install deps:
    pip install pyserial pillow --break-system-packages

Run:
    python lora_gui.py
"""

import threading
import time
import os
import io

import serial
import serial.tools.list_ports
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# ---- must mirror the firmware exactly ----
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
META_OVERHEAD_ESTIMATE = 2 + 40   # [type][fnameLen] + generous filename allowance
CHUNK_SX1278 = 240                # raw-binary payload bytes per SX1278 packet
CHUNK_RYLR = 128                  # base64-text payload bytes per RYLR packet
HEADER_OVERHEAD_RAW = 9           # SX1278 binary chunk header size (see firmware)
HEADER_OVERHEAD_B64 = 15          # RYLR ascii "recip,sess,tot,idx,len," header (approx)
MAX_CHUNKS_FIRMWARE = 4200        # matches Transfer::received[MAX_CHUNKS] on the slave
SAFE_CHUNK_LIMIT = 4000           # leave a margin

IMAGE_EXTS = {".png": "PNG", ".jpg": "JPG", ".jpeg": "JPG", ".bmp": "OTHER", ".gif": "OTHER"}

# FIX: previously missing .xlsx/.xls/.csv/.txt -- these fell through to
# the generic "OTHER" default via guess_file_type()'s fallback, which
# is harmless for delivery (the real filename/extension is still sent
# and preserved by the receiver) but showed the wrong type label in
# this GUI and in STATUS logging. Listed explicitly now.
DOC_EXTS = {
    ".pdf": "PDF", ".docx": "DOCX", ".doc": "DOCX",
    ".pptx": "PPTX", ".ppt": "PPTX",
    ".xlsx": "OTHER", ".xls": "OTHER", ".csv": "OTHER", ".txt": "TEXT",
}


def guess_file_type(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in IMAGE_EXTS:
        return IMAGE_EXTS[ext]
    if ext in DOC_EXTS:
        return DOC_EXTS[ext]
    return "OTHER"


def estimate_chunks_sx1278(plain_len: int) -> int:
    """SX1278 path: metadata + nonce+tag+ciphertext sent as RAW binary, no base64."""
    raw_len = META_OVERHEAD_ESTIMATE + GCM_NONCE_BYTES + GCM_TAG_BYTES + plain_len
    usable = max(1, CHUNK_SX1278)
    return (raw_len + usable - 1) // usable


def estimate_chunks_rylr(plain_len: int) -> int:
    """RYLR path: metadata + nonce+tag+ciphertext base64-encoded, then chunked as text."""
    raw_len = META_OVERHEAD_ESTIMATE + GCM_NONCE_BYTES + GCM_TAG_BYTES + plain_len
    b64_len = ((raw_len + 2) // 3) * 4
    usable = max(1, CHUNK_RYLR)
    return (b64_len + usable - 1) // usable


class LoraGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("LoRa Master Test GUI (AES-128-GCM encrypted link)")
        self.root.geometry("700x760")

        self.ser = None
        self.reader_thread = None
        self.stop_reader = False
        self.sending = False   # true while a send worker thread is active -- guards against
                                # overlapping writes to the serial port, which corrupts framing

        self._build_ui()
        self._refresh_ports()

    # ---------------- UI ----------------

    def _build_ui(self):
        pad = {"padx": 8, "pady": 6}

        # --- Connection frame ---
        conn = ttk.LabelFrame(self.root, text="Connection")
        conn.pack(fill="x", **pad)

        ttk.Label(conn, text="Port:").grid(row=0, column=0, padx=4, pady=4)
        self.port_var = tk.StringVar()
        self.port_combo = ttk.Combobox(conn, textvariable=self.port_var, width=20)
        self.port_combo.grid(row=0, column=1, padx=4, pady=4)

        ttk.Button(conn, text="Refresh", command=self._refresh_ports).grid(row=0, column=2, padx=4)
        ttk.Button(conn, text="Connect", command=self._connect).grid(row=0, column=3, padx=4)
        ttk.Button(conn, text="Disconnect", command=self._disconnect).grid(row=0, column=4, padx=4)
        self.stop_btn = ttk.Button(conn, text="⏹ STOP / Reset Master", command=self._stop_transfer)
        self.stop_btn.grid(row=0, column=5, padx=4)

        self.conn_status = ttk.Label(conn, text="Disconnected", foreground="red")
        self.conn_status.grid(row=0, column=6, padx=8)

        ttk.Label(conn, text="🔒 AES-128-GCM (encrypted in firmware)",
                  foreground="#2a7", font=("", 9, "italic")).grid(row=1, column=0, columnspan=6, sticky="w", padx=4)

        # --- Radio frame ---
        radio_frame = ttk.LabelFrame(self.root, text="Radio")
        radio_frame.pack(fill="x", **pad)
        ttk.Label(radio_frame, text="Manual override (leave on AUTO for adaptive selection):").grid(
            row=0, column=0, columnspan=3, sticky="w", padx=4)
        ttk.Button(radio_frame, text="AUTO", command=lambda: self._send_raw_line("FORCE:AUTO")).grid(row=1, column=0, padx=4, pady=4)
        ttk.Button(radio_frame, text="Force SX1278", command=lambda: self._send_raw_line("FORCE:SX")).grid(row=1, column=1, padx=4, pady=4)
        ttk.Button(radio_frame, text="Force RYLR896", command=lambda: self._send_raw_line("FORCE:RYLR")).grid(row=1, column=2, padx=4, pady=4)
        ttk.Button(radio_frame, text="STATUS", command=lambda: self._send_raw_line("STATUS")).grid(row=1, column=3, padx=4, pady=4)

        # --- Send text frame ---
        text_frame = ttk.LabelFrame(self.root, text="Send Text Message")
        text_frame.pack(fill="x", **pad)

        ttk.Label(text_frame, text="Node (hex):").grid(row=0, column=0, padx=4, pady=4)
        self.node_var_text = tk.StringVar(value="02")
        ttk.Entry(text_frame, textvariable=self.node_var_text, width=6).grid(row=0, column=1, padx=4)

        self.msg_var = tk.StringVar()
        ttk.Entry(text_frame, textvariable=self.msg_var, width=40).grid(row=0, column=2, padx=4)
        self.send_text_btn = ttk.Button(text_frame, text="Send", command=self._send_text)
        self.send_text_btn.grid(row=0, column=3, padx=4)

        # --- Send file/image frame ---
        file_frame = ttk.LabelFrame(self.root, text="Send Image / File (image, PDF, DOCX, XLSX, or any file)")
        file_frame.pack(fill="x", **pad)

        ttk.Label(file_frame, text="Node (hex):").grid(row=0, column=0, padx=4, pady=4)
        self.node_var_file = tk.StringVar(value="02")
        ttk.Entry(file_frame, textvariable=self.node_var_file, width=6).grid(row=0, column=1, padx=4)

        self.file_path_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path_var, width=36).grid(row=0, column=2, padx=4)
        ttk.Button(file_frame, text="Browse...", command=self._browse_file).grid(row=0, column=3, padx=4)

        # Fidelity mode (only meaningful for images -- non-image files are
        # always sent byte-exact regardless of this setting).
        self.fidelity_var = tk.StringVar(value="compressed")
        fid_frame = ttk.Frame(file_frame)
        fid_frame.grid(row=1, column=0, columnspan=5, sticky="w", padx=4)
        ttk.Radiobutton(fid_frame, text="Exact / Lossless (original file bytes, no resize)",
                        variable=self.fidelity_var, value="lossless",
                        command=self._update_estimate).pack(side="left", padx=(0, 12))
        ttk.Radiobutton(fid_frame, text="Compressed (resize + JPEG/PNG, images only)",
                        variable=self.fidelity_var, value="compressed",
                        command=self._on_fidelity_change).pack(side="left")

        self.resize_row = ttk.Frame(file_frame)
        self.resize_row.grid(row=2, column=0, columnspan=5, sticky="w", padx=4)

        self.grayscale_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.resize_row, text="Grayscale (smaller, B/W)",
                         variable=self.grayscale_var,
                         command=self._update_estimate).grid(row=0, column=4, sticky="w", padx=4)

        ttk.Label(self.resize_row, text="Target max dimension (px):").grid(row=0, column=0, sticky="e")
        self.resize_dim_var = tk.StringVar(value="192")
        dim_entry = ttk.Entry(self.resize_row, textvariable=self.resize_dim_var, width=6)
        dim_entry.grid(row=0, column=1, padx=4)
        dim_entry.bind("<KeyRelease>", lambda e: self._update_estimate())

        ttk.Label(self.resize_row, text="Format:").grid(row=1, column=0, sticky="e", padx=4)
        self.format_var = tk.StringVar(value="JPEG")
        format_combo = ttk.Combobox(self.resize_row, textvariable=self.format_var, width=8,
                                     values=["JPEG", "PNG"], state="readonly")
        format_combo.grid(row=1, column=1, sticky="w", padx=4)
        format_combo.bind("<<ComboboxSelected>>", lambda e: self._on_format_change())

        ttk.Label(self.resize_row, text="JPEG quality:").grid(row=1, column=2, sticky="e")
        self.quality_var = tk.IntVar(value=85)
        self.quality_scale = ttk.Scale(self.resize_row, from_=10, to=95, variable=self.quality_var,
                                        orient="horizontal", command=lambda v: self._update_estimate())
        self.quality_scale.grid(row=1, column=3, sticky="ew", padx=4)
        self.quality_label = ttk.Label(self.resize_row, text="85")
        self.quality_label.grid(row=1, column=4, padx=2)

        ttk.Label(file_frame, text="Radio for estimate:").grid(row=3, column=0, sticky="e", padx=4)
        self.radio_estimate_var = tk.StringVar(value="SX1278 (raw binary)")
        ttk.Combobox(file_frame, textvariable=self.radio_estimate_var, width=22, state="readonly",
                     values=["SX1278 (raw binary)", "RYLR896 (base64 text)"]
                     ).grid(row=3, column=1, columnspan=2, sticky="w", padx=4)
        self.radio_estimate_var.trace_add("write", lambda *a: self._update_estimate())

        self.send_file_btn = ttk.Button(file_frame, text="Send File", command=self._send_file_clicked)
        self.send_file_btn.grid(row=4, column=0, columnspan=2, pady=6)

        self.size_label = ttk.Label(file_frame, text="", justify="left")
        self.size_label.grid(row=5, column=0, columnspan=5, sticky="w", padx=4)

        self.estimate_label = ttk.Label(file_frame, text="", justify="left", foreground="#333")
        self.estimate_label.grid(row=6, column=0, columnspan=5, sticky="w", padx=4)

        # --- Progress frame ---
        prog_frame = ttk.LabelFrame(self.root, text="Transfer Progress")
        prog_frame.pack(fill="x", **pad)

        self.progress = ttk.Progressbar(prog_frame, length=600, mode="determinate")
        self.progress.pack(padx=8, pady=8)

        self.progress_label = ttk.Label(prog_frame, text="Idle")
        self.progress_label.pack(padx=8, pady=4)

        # --- Log frame ---
        log_frame = ttk.LabelFrame(self.root, text="Serial Log (Master)")
        log_frame.pack(fill="both", expand=True, **pad)

        self.log_text = tk.Text(log_frame, height=14, wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=4, pady=4)
        scrollbar = ttk.Scrollbar(self.log_text, command=self.log_text.yview)
        self.log_text.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        self._on_fidelity_change()

    def _on_fidelity_change(self):
        is_compressed = self.fidelity_var.get() == "compressed"
        for child in self.resize_row.winfo_children():
            child.configure(state="normal" if is_compressed else "disabled")
        if is_compressed:
            self._on_format_change()
        self._update_estimate()

    def _on_format_change(self):
        is_jpeg = self.format_var.get() == "JPEG"
        state = "normal" if is_jpeg else "disabled"
        self.quality_scale.config(state=state)
        self._update_estimate()

    # ---------------- estimation ----------------

    def _update_estimate(self):
        self.quality_label.config(text=str(int(self.quality_var.get())))
        path = self.file_path_var.get()
        if not path or not os.path.isfile(path):
            self.estimate_label.config(text="")
            return
        try:
            data, _ftype = self._prepare_file_bytes(path, log=False)
        except Exception as e:
            self.estimate_label.config(text=f"(Could not estimate: {e})", foreground="#b33")
            return

        if "SX1278" in self.radio_estimate_var.get():
            chunks = estimate_chunks_sx1278(len(data))
        else:
            chunks = estimate_chunks_rylr(len(data))

        if chunks > MAX_CHUNKS_FIRMWARE:
            msg = (f"⚠ {len(data)} bytes -> ~{chunks} chunks EXCEEDS slave's MAX_CHUNKS="
                   f"{MAX_CHUNKS_FIRMWARE}. Switch to Compressed mode or lower resolution/quality.")
            self.estimate_label.config(text=msg, foreground="#b33")
        elif chunks > SAFE_CHUNK_LIMIT:
            self.estimate_label.config(
                text=f"⚠ {len(data)} bytes -> ~{chunks} chunks. Close to the {MAX_CHUNKS_FIRMWARE} limit.",
                foreground="#c80")
        else:
            self.estimate_label.config(
                text=f"{len(data)} bytes -> ~{chunks} chunks on this radio.",
                foreground="#333")

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
        if self.sending:
            messagebox.showwarning("Busy", "A transfer is in progress -- wait for it to finish first.")
            return
        port = self.port_var.get()
        if not port:
            messagebox.showwarning("No port", "Select a serial port first.")
            return
        try:
            # IMPORTANT: opening a pyserial port normally toggles DTR/RTS,
            # which most ESP32 dev boards wire to EN/IO0 -- that RESETS the
            # board on every connect. Setting dtr/rts False *before*
            # opening avoids that reset pulse.
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
        if self.sending:
            if not messagebox.askyesno("Transfer in progress",
                                        "A send is still in progress. Disconnecting now will likely "
                                        "corrupt it. Disconnect anyway?"):
                return
        self.stop_reader = True
        if self.ser and self.ser.is_open:
            self.ser.close()
        self.conn_status.config(text="Disconnected", foreground="red")
        self.sending = False
        self._set_busy(False)
        self._log("Disconnected")

    def _stop_transfer(self):
        # There is no in-firmware "abort a transfer" command -- the master
        # is busy inside a blocking send loop and can't listen for new
        # serial commands until it finishes or gives up. The only real way
        # to stop a stuck transfer from here is to reset the master board,
        # which we can now do deliberately (rather than by accident) using
        # the same DTR pulse that used to reset it unintentionally.
        if not self._check_connected():
            return
        if not messagebox.askyesno("Stop / Reset Master",
                                    "This will reset the MASTER board to forcibly stop the current "
                                    "transfer. Any in-progress send will be lost. Continue?"):
            return
        try:
            self.ser.dtr = True
            time.sleep(0.1)
            self.ser.dtr = False
            self._log("[GUI] Sent reset pulse to master board.")
        except Exception as e:
            self._log(f"[GUI] Reset failed: {e}")
        self.sending = False
        self._set_busy(False)
        self._update_progress(0, "Stopped (master reset)")

    def _read_loop(self):
        buf = b""
        while not self.stop_reader and self.ser and self.ser.is_open:
            try:
                chunk = self.ser.read(256)
                if chunk:
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        self._handle_line(line.decode(errors="replace").strip())
            except Exception as e:
                self._log(f"[ERROR] Read error: {e}")
                break

    def _handle_line(self, line):
        if not line:
            return
        self.root.after(0, self._log, line)

        if line.startswith("PROGRESS:"):
            try:
                _, idx, total = line.split(":")
                idx, total = int(idx), int(total)
                pct = int(((idx + 1) / total) * 100)
                self.root.after(0, self._update_progress, pct,
                                f"Sending chunk {idx + 1}/{total} ({pct}%) [encrypted]")
            except Exception:
                pass

        elif line.startswith("DONE:"):
            try:
                _, total, elapsed_ms = line.split(":")
                elapsed_s = int(elapsed_ms) / 1000.0
                self.root.after(0, self._update_progress, 100,
                                 f"All {total} chunks ACKed in {elapsed_s:.2f}s "
                                 f"(check the slave monitor for the actual decrypt result)")
            except Exception:
                pass
            self.root.after(0, self._set_busy, False)

        elif line.startswith("FAILED:"):
            try:
                _, idx = line.split(":")
                self.root.after(0, self._update_progress, None,
                                 f"FAILED at chunk {idx} - transfer aborted")
            except Exception:
                pass
            self.root.after(0, self._set_busy, False)

        elif line.startswith("[TX] Using"):
            self.root.after(0, self._update_progress, 0, line)

    def _set_busy(self, busy: bool):
        self.sending = busy
        state = "disabled" if busy else "normal"
        self.send_text_btn.config(state=state)
        self.send_file_btn.config(state=state)

    def _log(self, msg):
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")

    def _update_progress(self, pct, label_text):
        if pct is not None:
            self.progress["value"] = pct
        self.progress_label.config(text=label_text)

    # ---------------- Send actions ----------------

    def _send_raw_line(self, line):
        if not self._check_connected():
            return
        if self.sending:
            messagebox.showwarning("Busy", "Wait for the current transfer to finish (or hit STOP) "
                                            "before sending FORCE/STATUS commands -- writing to the "
                                            "port mid-transfer will corrupt the file bytes in flight.")
            return
        self.ser.write((line + "\n").encode())
        self._log(f">> {line}")

    def _send_text(self):
        if not self._check_connected():
            return
        if self.sending:
            messagebox.showwarning("Busy", "A transfer is already in progress -- "
                                            "wait for it to finish (or hit STOP) before sending more.")
            return
        node = self.node_var_text.get().strip()
        msg = self.msg_var.get()
        if not node or not msg:
            messagebox.showwarning("Missing data", "Enter node and message.")
            return
        # Text still goes through the master's blocking send path (same as
        # files), so treat it as a real transfer for busy-locking purposes
        # too -- this is what previously let a text send collide with an
        # in-flight file send and corrupt both.
        self._set_busy(True)
        line = f"{node} {msg}\n"
        self.ser.write(line.encode())
        self._log(f">> {line.strip()}  (will be AES-128-GCM encrypted by master before TX)")

    def _browse_file(self):
        # "All Files" is listed FIRST on purpose -- Windows' file dialog
        # defaults to whichever filter is first in this list, so if a
        # narrower filter came first, folders containing only (say) PDFs
        # would look empty until you manually switched the dropdown.
        path = filedialog.askopenfilename(
            filetypes=[
                ("All files", "*.*"),
                ("All supported", ("*.png", "*.jpg", "*.jpeg", "*.bmp", "*.gif",
                                    "*.pdf", "*.docx", "*.doc", "*.pptx", "*.ppt",
                                    "*.txt", "*.csv", "*.xlsx", "*.zip")),
                ("Images", ("*.png", "*.jpg", "*.jpeg", "*.bmp", "*.gif")),
                ("Documents", ("*.pdf", "*.docx", "*.doc", "*.pptx", "*.ppt", "*.txt", "*.csv", "*.xlsx")),
            ]
        )
        if path:
            self.file_path_var.set(path)
            size_kb = os.path.getsize(path) / 1024
            self.size_label.config(text=f"Original size: {size_kb:.2f} KB  |  type guess: {guess_file_type(path)}")
            self._update_estimate()

    def _send_file_clicked(self):
        if not self._check_connected():
            return
        if self.sending:
            messagebox.showwarning("Busy", "A transfer is already in progress -- "
                                            "wait for it to finish (or hit STOP) before sending more.")
            return
        path = self.file_path_var.get()
        if not path or not os.path.isfile(path):
            messagebox.showwarning("No file", "Choose a valid file first.")
            return

        node = self.node_var_file.get().strip()
        if not node:
            messagebox.showwarning("Missing node", "Enter target node hex address.")
            return

        try:
            data, ftype = self._prepare_file_bytes(path, log=False)
        except Exception as e:
            messagebox.showerror("Prepare failed", str(e))
            return

        if "SX1278" in self.radio_estimate_var.get():
            chunks = estimate_chunks_sx1278(len(data))
        else:
            chunks = estimate_chunks_rylr(len(data))

        if chunks > MAX_CHUNKS_FIRMWARE:
            if not messagebox.askyesno(
                    "Likely to fail",
                    f"Estimated {chunks} chunks exceeds the slave's MAX_CHUNKS="
                    f"{MAX_CHUNKS_FIRMWARE}. This transfer will very likely fail "
                    f"or arrive partial. Send anyway?"):
                return
        elif chunks > 300:
            eta_min = (chunks * 0.3) / 60  # rough: ~300ms/chunk on a clean link
            if not messagebox.askyesno(
                    "Large transfer",
                    f"~{chunks} chunks estimated. On a clean link this typically takes "
                    f"roughly {eta_min:.1f}+ minutes (longer if retry passes are needed). "
                    f"Continue?"):
                return

        self._set_busy(True)
        threading.Thread(target=self._send_file_worker, args=(path, node, ftype), daemon=True).start()

    def _send_file_worker(self, path, node, ftype):
        try:
            data, ftype = self._prepare_file_bytes(path, log=True)
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Prepare failed", str(e))
            self.root.after(0, self._set_busy, False)
            return

        size = len(data)
        fname = os.path.basename(path)[:60]
        self.root.after(0, self._log, f"Prepared {size} plaintext bytes (type={ftype}, name={fname}) "
                                       f"to send to node {node} (master will AES-128-GCM encrypt before TX)")
        self.root.after(0, self._update_progress, 0, f"Sending {size} bytes...")

        cmd = f"SENDFILE:{node}:{size}:{ftype}:{fname}\n"
        try:
            self.ser.write(cmd.encode())
            time.sleep(0.1)
            self.ser.write(data)
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Send failed", str(e))
            self.root.after(0, self._set_busy, False)
        # NOTE: busy is cleared when DONE:/FAILED: is seen in _handle_line,
        # not here -- the write finishing just means the bytes left the PC,
        # not that the master finished chunking/ACKing them over the air.

    def _prepare_file_bytes(self, path, log=True):
        """Returns (bytes_to_send, firmware_type_string).

        Non-image files (PDF/DOCX/XLSX/other) always go byte-exact
        regardless of the fidelity setting -- resize/recompress only
        applies to images. Images go byte-exact too when "Exact /
        Lossless" is selected.
        """
        ftype = guess_file_type(path)

        is_image = ftype in ("PNG", "JPG") or os.path.splitext(path)[1].lower() in IMAGE_EXTS
        if not is_image or self.fidelity_var.get() == "lossless" or not PIL_AVAILABLE:
            with open(path, "rb") as f:
                data = f.read()
            if log:
                self.root.after(0, self._log, f"Sending original bytes untouched ({len(data)} bytes)")
            return data, ftype

        # Compressed image path.
        try:
            max_dim = int(self.resize_dim_var.get())
        except ValueError:
            max_dim = 192

        img = Image.open(path)
        img.thumbnail((max_dim, max_dim))

        fmt = self.format_var.get()

        if self.grayscale_var.get():
            img = img.convert("L")
        elif fmt == "JPEG" and img.mode in ("RGBA", "P", "LA"):
            img = img.convert("RGBA") if img.mode != "RGBA" else img
            bg = Image.new("RGB", img.size, (255, 255, 255))
            bg.paste(img, mask=img.split()[-1])
            img = bg
        elif img.mode == "P":
            img = img.convert("RGB")

        buf = io.BytesIO()
        if fmt == "JPEG":
            quality = int(self.quality_var.get())
            img.save(buf, format="JPEG", quality=quality, optimize=True)
            out_type = "JPG"
        else:
            img.save(buf, format="PNG", optimize=True)
            out_type = "PNG"
        result = buf.getvalue()

        if log:
            self.root.after(0, self._log,
                             f"Resized to {img.size}, {fmt} = {len(result)} bytes "
                             f"(original was {os.path.getsize(path)} bytes)")
        return result, out_type

    def _check_connected(self):
        if not self.ser or not self.ser.is_open:
            messagebox.showwarning("Not connected", "Connect to the master's serial port first.")
            return False
        return True


if __name__ == "__main__":
    root = tk.Tk()
    app = LoraGUI(root)
    root.mainloop()
