/*
  LoRa MASTER — dual radio (SX1278 + RYLR896) with failover
  AES-128-GCM encryption, adaptive radio selection, multi-file-type support.

  ------------------------------------------------------------------
  FIX IN THIS VERSION: SELECTIVE MULTI-PASS RETRY (this is why larger
  files like a 60KB PDF were stalling out and only partially arriving,
  while a smaller/compressed image "worked")
  ------------------------------------------------------------------
  The previous send loop retried a chunk up to 8 times and then, if it
  still wasn't ACKed, ABORTED THE ENTIRE TRANSFER -- every chunk after
  that point was simply never sent. The slave then sat there with a
  hole in the middle of its buffer until its own (also broken) timeout
  fired, and reported a "partial recovery" that was really "the master
  gave up 200 chunks early."

  This hit bigger raw (uncompressed) files hardest just by dice-roll:
  more chunks == more chances for one link hiccup to nuke the whole
  transfer, and PDFs/DOCX/XLSX are always sent byte-exact (no
  resize/recompress like the image path has), so they're the most
  chunk-heavy case for a given file size.

  It also explains the garbled RXMETA you were seeing: the file
  type/filename metadata lives in the FIRST bytes of plaintext, i.e.
  inside chunk index 0. If chunk 0 specifically was one of the ones
  that got skipped when the master bailed out, the slave's best-effort
  decrypt produces garbage for the type byte and filename -- which is
  why it fell back to saving as .bin with a junk name.

  FIX: the master now does repeated PASSES over the chunk list. Each
  pass only (re)sends chunks that are still unacked. It keeps looping
  passes (with a growing per-chunk retry budget) until either every
  chunk is acked, or a hard pass ceiling is hit. A single bad chunk --
  even chunk 0 -- no longer kills the rest of the file.
  ------------------------------------------------------------------
  OTHER CHANGES (unchanged from before)
  ------------------------------------------------------------------
  - Single-buffer in-place AES-GCM encryption (see earlier notes) --
    peak RAM ~1x file size on the SX1278 raw path.
  - File types: TEXT, PNG, JPG, PDF, DOCX, PPTX, OTHER.
  - Metadata header [1 byte type][1 byte fnameLen][filename] is
    prepended before encryption so the receiver reconstructs the exact
    file type/name.
  - SX1278 chunks are raw binary; RYLR896 stays base64.
  - Adaptive radio selection (SX1278 preferred above ~400 bytes),
    manual FORCE:SX / FORCE:RYLR / FORCE:AUTO still available.
  - Text messages go through the exact same encrypt/chunk/ACK path as
    files -- no character filtering anywhere in the pipeline.

  Serial commands (115200 baud):
    FORCE:SX | FORCE:RYLR | FORCE:AUTO | STATUS
    <NODE_HEX> <text message>                     e.g. 02 Hello there! 123 #$%
    SENDFILE:<NODE_HEX>:<size>:<type>:<filename>   then raw bytes
      type: TEXT | PNG | JPG | PDF | DOCX | PPTX | OTHER
  ------------------------------------------------------------------
*/

#include <SPI.h>
#include <LoRa.h>
#include <HardwareSerial.h>
#include "mbedtls/base64.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "esp_random.h"
#include "esp_heap_caps.h"

const int csPin    = 10;
const int resetPin =  9;
const int irqPin   =  8;

#define RYLR_RX_PIN  18
#define RYLR_TX_PIN  17
#define RYLR_BAUD    115200
HardwareSerial rylrSerial(1);

typedef enum { RADIO_NONE=0, RADIO_SX1278=1, RADIO_RYLR=2 } RadioID;
RadioID activeRadio   = RADIO_NONE;
RadioID overrideRadio = RADIO_NONE;
bool    sx1278_ok     = false;
bool    rylr_ok       = false;

#define SPREADING_FACTOR 7
#define SX_CHUNK_MAGIC 0xC5

// Declared here (not further down) so the Arduino IDE's auto-generated
// prototypes -- which are inserted at the very top of the file -- can
// see this type. Moving it below any function that uses it causes
// "'FileType' does not name a type" compile errors.
enum FileType : uint8_t { FT_TEXT=0, FT_PNG=1, FT_JPG=2, FT_PDF=3, FT_DOCX=4, FT_PPTX=5, FT_OTHER=6 };

#define CHUNK_SX1278  240   // raw-binary payload bytes per SX1278 packet
#define CHUNK_RYLR    128   // base64-text payload bytes per RYLR packet
#define ADAPTIVE_SIZE_THRESHOLD 400  // bytes; above this, prefer SX1278

const byte masterAddress = 0xAB;
const int  syncWord      = 0x23;

// =================== retry tuning ===================
// Multi-pass selective retry: pass 1 is cheap (fast timeout, few
// retries per chunk) so a clean link finishes fast; later passes are
// more patient, on the theory that anything still missing by then is
// probably a marginal-link chunk that needs a longer ACK window.
#define MAX_PASSES        6
#define PASS1_RETRIES     2
#define LATER_RETRIES     4
#define PASS1_ACK_MS      1200
#define LATER_ACK_MS      1800
#define INTER_ATTEMPT_MS  150
#define INTER_PASS_MS     300

// =================== memory helper ===================
// Prefer PSRAM for big transfer buffers if the board has it; fall back
// to normal heap automatically otherwise. Safe to call unconditionally.
void* bigMalloc(size_t n) {
    void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (p) return p;
    return malloc(n);
}

// =================== AES-128-GCM CRYPTO ===================
static const char* CRYPTO_PASSPHRASE = "LAUDENBHOJYAM12";

#define AES_KEY_BYTES   16
#define GCM_NONCE_BYTES 12
#define GCM_TAG_BYTES   16

uint8_t g_aesKey[AES_KEY_BYTES];
mbedtls_gcm_context g_gcm;

void cryptoInit() {
    uint8_t hash[32];
    mbedtls_sha256((const unsigned char*)CRYPTO_PASSPHRASE, strlen(CRYPTO_PASSPHRASE), hash, 0);
    memcpy(g_aesKey, hash, AES_KEY_BYTES);
    mbedtls_gcm_init(&g_gcm);
    int rc = mbedtls_gcm_setkey(&g_gcm, MBEDTLS_CIPHER_ID_AES, g_aesKey, AES_KEY_BYTES * 8);
    Serial.println(rc == 0 ? "[CRYPTO] AES-128-GCM key derived OK (HW-accelerated)"
                            : "[CRYPTO] FATAL: gcm_setkey failed rc=" + String(rc));
}

void cryptoRandomNonce(uint8_t* out12) {
    for (int i = 0; i < GCM_NONCE_BYTES; i += 4) {
        uint32_t r = esp_random();
        memcpy(out12 + i, &r, min(4, GCM_NONCE_BYTES - i));
    }
}

// In-place encrypt: input and output MAY be the same pointer (mbedTLS
// supports this for GCM since the cipher core is CTR mode). Tag is
// written straight to outTag16, which can point directly into your
// wire buffer -- no extra tag-sized allocation needed.
bool cryptoEncryptInPlace(uint8_t* buf, size_t len, const uint8_t* nonce12, uint8_t* outTag16) {
    int rc = mbedtls_gcm_crypt_and_tag(&g_gcm, MBEDTLS_GCM_ENCRYPT, len,
                                        nonce12, GCM_NONCE_BYTES, NULL, 0,
                                        buf, buf, GCM_TAG_BYTES, outTag16);
    return rc == 0;
}

// =================== radio init ===================

bool initSX1278() {
    SPI.begin(12, 13, 11, csPin);
    LoRa.setPins(csPin, resetPin, irqPin);
    if (!LoRa.begin(433E6)) { Serial.println("[SX1278] Init FAILED"); return false; }
    LoRa.setTxPower(20, PA_OUTPUT_PA_BOOST_PIN);
    LoRa.setSpreadingFactor(SPREADING_FACTOR);
    LoRa.setSignalBandwidth(125E3);
    LoRa.setCodingRate4(8);
    LoRa.setSyncWord(syncWord);
    LoRa.enableCrc();
    Serial.println("[SX1278] Init OK (TX=20dBm SF=" + String(SPREADING_FACTOR) + " CR=4/8, CRC on)");
    return true;
}

bool initRYLR() {
    rylrSerial.begin(RYLR_BAUD, SERIAL_8N1, RYLR_RX_PIN, RYLR_TX_PIN);
    delay(400);
    while (rylrSerial.available()) rylrSerial.read();

    auto atCmd = [&](const String& cmd) -> bool {
        rylrSerial.println(cmd);
        uint32_t t = millis(); String resp = "";
        while (millis() - t < 1500) {
            if (rylrSerial.available()) {
                resp += (char)rylrSerial.read();
                if (resp.indexOf("+OK") >= 0) return true;
                if (resp.indexOf("ERR") >= 0) {
                    Serial.println("[RYLR896] " + cmd + " -> " + resp);
                    return false;
                }
            }
        }
        Serial.println("[RYLR896] " + cmd + " -> TIMEOUT (no response)");
        return false;
    };

    bool ok = true;
    ok &= atCmd("AT+ADDRESS=1");
    ok &= atCmd("AT+NETWORKID=5");
    ok &= atCmd("AT+BAND=433000000");
    ok &= atCmd("AT+PARAMETER=10,7,1,7"); // SF10: more range margin than default SF7
    ok &= atCmd("AT+CRFOP=15");            // RYLR896's CRFOP max is 15 dBm
    Serial.println(ok ? "[RYLR896] Init OK" : "[RYLR896] Init FAILED");
    return ok;
}

void selectBestRadio(size_t payloadSizeHint = 0) {
    if (overrideRadio != RADIO_NONE) { activeRadio = overrideRadio; return; }
    if (payloadSizeHint > ADAPTIVE_SIZE_THRESHOLD) {
        activeRadio = sx1278_ok ? RADIO_SX1278 : (rylr_ok ? RADIO_RYLR : RADIO_NONE);
    } else {
        if (sx1278_ok)      activeRadio = RADIO_SX1278;
        else if (rylr_ok)   activeRadio = RADIO_RYLR;
        else                activeRadio = RADIO_NONE;
    }
}

const char* radioName(RadioID r) {
    switch(r) { case RADIO_SX1278: return "SX1278"; case RADIO_RYLR: return "RYLR896"; default: return "NONE"; }
}

int activeChunkSize() { return (activeRadio == RADIO_RYLR) ? CHUNK_RYLR : CHUNK_SX1278; }
bool activeUsesBase64() { return activeRadio == RADIO_RYLR; }

// =================== low-level send helpers ===================

bool rylrSendText(byte recipient, const String& payload) {
    String cmd = "AT+SEND=" + String(recipient) + "," + String(payload.length()) + "," + payload;
    rylrSerial.println(cmd);
    uint32_t t = millis(); String resp = "";
    while (millis() - t < 1500) {
        if (rylrSerial.available()) {
            resp += (char)rylrSerial.read();
            if (resp.indexOf("+OK") >= 0) return true;
            if (resp.indexOf("ERR") >= 0) return false;
        }
    }
    return false;
}

// Data chunk send: raw binary on SX1278 (magic-prefixed), base64 text on RYLR.
bool sendChunkPacket(byte recipient, byte sessionId, uint16_t totalChunks,
                      uint16_t chunkIndex, byte chunkLength, const uint8_t* chunk) {
    if (activeRadio == RADIO_SX1278) {
        uint8_t hdr[9];
        hdr[0] = recipient; hdr[1] = masterAddress; hdr[2] = SX_CHUNK_MAGIC;
        hdr[3] = sessionId;
        hdr[4] = (byte)(totalChunks >> 8); hdr[5] = (byte)(totalChunks & 0xFF);
        hdr[6] = (byte)(chunkIndex >> 8);  hdr[7] = (byte)(chunkIndex & 0xFF);
        hdr[8] = chunkLength;
        LoRa.beginPacket();
        LoRa.write(hdr, sizeof(hdr));
        LoRa.write(chunk, chunkLength);
        return LoRa.endPacket();
    } else if (activeRadio == RADIO_RYLR) {
        char header[32];
        snprintf(header, sizeof(header), "%02X,%02X,%04X,%04X,%02X,",
                 recipient, sessionId, totalChunks, chunkIndex, chunkLength);
        String payload = String(header);
        for (int i = 0; i < chunkLength; i++) payload += (char)chunk[i];
        if ((int)payload.length() > CHUNK_RYLR + 30) {
            Serial.println("[RYLR] Payload too large for chunk size");
            return false;
        }
        return rylrSendText(recipient, payload);
    }
    return false;
}

bool waitForLine(const String& mustContain, String& outLine, uint32_t timeoutMs) {
    uint32_t start = millis();
    if (activeRadio == RADIO_SX1278) {
        while (millis() - start < timeoutMs) {
            int packetSize = LoRa.parsePacket();
            if (packetSize) {
                byte to = LoRa.read();
                if (to == masterAddress && LoRa.available()) {
                    byte from = LoRa.read();
                    String msg = "";
                    while (LoRa.available()) msg += (char)LoRa.read();
                    if (msg.indexOf(mustContain) >= 0) { outLine = msg; return true; }
                }
            }
        }
    } else if (activeRadio == RADIO_RYLR) {
        static String buf = "";
        while (millis() - start < timeoutMs) {
            while (rylrSerial.available()) {
                char c = rylrSerial.read();
                if (c == '\n') {
                    if (buf.indexOf(mustContain) >= 0) { outLine = buf; buf = ""; return true; }
                    buf = "";
                } else if (c != '\r') buf += c;
            }
        }
    }
    return false;
}

bool waitForAck(uint16_t expectChunkIndex, uint32_t timeoutMs) {
    String line;
    return waitForLine("ACK:" + String(expectChunkIndex), line, timeoutMs);
}

// =================== file type mapping ===================

FileType fileTypeFromString(const String& s) {
    String u = s; u.toUpperCase();
    if (u == "PNG")  return FT_PNG;
    if (u == "JPG" || u == "JPEG") return FT_JPG;
    if (u == "PDF")  return FT_PDF;
    if (u == "DOCX" || u == "DOC") return FT_DOCX;
    if (u == "PPTX" || u == "PPT") return FT_PPTX;
    if (u == "TEXT") return FT_TEXT;
    return FT_OTHER;
}

// =================== chunked send (single-buffer, in-place encrypt,
//                      multi-pass selective retry) ===================

bool sendChunkedBinary(byte recipient, const uint8_t* plaintext, size_t len, byte sessionId,
                        FileType ftype, const String& filename) {
    uint32_t startTime = millis();

    uint8_t fnameLen = (uint8_t)min((size_t)200, filename.length());
    size_t metaLen = 2 + fnameLen;
    size_t innerLen = metaLen + len;                          // metadata + your data
    size_t rawLen   = GCM_NONCE_BYTES + GCM_TAG_BYTES + innerLen;

    // ---- ONE buffer for the whole transfer: [nonce(12)][tag(16)][metadata+data] ----
    uint8_t* raw = (uint8_t*)bigMalloc(rawLen);
    if (!raw) {
        Serial.println("[MEM] Failed to allocate " + String(rawLen) + " bytes -- transfer too large for available RAM");
        Serial.println("FAILED:0");
        return false;
    }

    uint8_t* noncePtr = raw;
    uint8_t* tagPtr   = raw + GCM_NONCE_BYTES;
    uint8_t* innerPtr = raw + GCM_NONCE_BYTES + GCM_TAG_BYTES;

    cryptoRandomNonce(noncePtr);
    innerPtr[0] = (uint8_t)ftype;
    innerPtr[1] = fnameLen;
    memcpy(innerPtr + 2, filename.c_str(), fnameLen);
    memcpy(innerPtr + metaLen, plaintext, len);

    if (!cryptoEncryptInPlace(innerPtr, innerLen, noncePtr, tagPtr)) {
        Serial.println("[CRYPTO] Encrypt failed");
        free(raw);
        Serial.println("FAILED:0");
        return false;
    }

    // ---- Encode for the wire. SX1278: send `raw` as-is (no extra copy).
    //      RYLR: base64 needs a second buffer, freed right after sending. ----
    bool useB64 = activeUsesBase64();
    uint8_t* wire; size_t wireLen;
    if (useB64) {
        size_t b64Len = 0;
        mbedtls_base64_encode(NULL, 0, &b64Len, raw, rawLen);
        wire = (uint8_t*)bigMalloc(b64Len + 1);
        if (!wire) {
            Serial.println("[MEM] Failed to allocate base64 buffer (" + String(b64Len) + " bytes)");
            free(raw);
            Serial.println("FAILED:0");
            return false;
        }
        size_t actualLen = 0;
        mbedtls_base64_encode(wire, b64Len, &actualLen, raw, rawLen);
        wireLen = actualLen;
        free(raw);
    } else {
        wire = raw;
        wireLen = rawLen;
    }

    int chunkSize = activeChunkSize();
    uint16_t totalChunks = (wireLen + chunkSize - 1) / chunkSize;

    // ---- acked[] tracks which chunks have been confirmed. We loop
    // passes over the *unacked* set only, so one stubborn chunk (even
    // chunk 0, which carries the file-type/filename metadata) never
    // takes the rest of the transfer down with it. ----
    bool* acked = (bool*)calloc(totalChunks, sizeof(bool));
    if (!acked) {
        Serial.println("[MEM] Failed to allocate ack-tracking array");
        free(wire);
        Serial.println("FAILED:0");
        return false;
    }
    uint16_t remaining = totalChunks;
    int pass = 0;

    while (remaining > 0 && pass < MAX_PASSES) {
        pass++;
        int retriesThisPass = (pass == 1) ? PASS1_RETRIES : LATER_RETRIES;
        uint32_t ackTimeoutThisPass = (pass == 1) ? PASS1_ACK_MS : LATER_ACK_MS;

        for (uint16_t i = 0; i < totalChunks; i++) {
            if (acked[i]) continue;

            size_t offset = (size_t)i * chunkSize;
            size_t thisLen = min((size_t)chunkSize, wireLen - offset);

            bool ackReceived = false;
            int attempt = 0;
            int retries = retriesThisPass;

            while (!ackReceived && retries > 0) {
                attempt++;
                bool sent = sendChunkPacket(recipient, sessionId, totalChunks, i, (byte)thisLen, wire + offset);
                if (!sent) {
                    Serial.println("[TX] pass " + String(pass) + " chunk " + String(i) +
                                    " attempt " + String(attempt) + ": send FAILED on " + String(radioName(activeRadio)));
                } else {
                    ackReceived = waitForAck(i, ackTimeoutThisPass);
                    if (!ackReceived) {
                        Serial.println("[TX] pass " + String(pass) + " chunk " + String(i) +
                                        " attempt " + String(attempt) + ": sent OK but no ACK within " +
                                        String(ackTimeoutThisPass) + "ms");
                    }
                }
                if (!ackReceived) { retries--; delay(INTER_ATTEMPT_MS); }
            }

            if (ackReceived) {
                acked[i] = true;
                remaining--;
                Serial.println("PROGRESS:" + String(i) + ":" + String(totalChunks));
            }
        }

        if (remaining > 0 && pass < MAX_PASSES) {
            Serial.println("[TX] pass " + String(pass) + " complete: " + String(remaining) +
                            "/" + String(totalChunks) + " chunks still unacked -- starting pass " + String(pass + 1));
            delay(INTER_PASS_MS);
        }
    }

    free(acked);

    if (remaining > 0) {
        Serial.println("[TX] gave up after " + String(pass) + " passes: " + String(remaining) +
                        "/" + String(totalChunks) + " chunks never acked");
        Serial.println("FAILED:" + String(totalChunks - remaining));
        free(wire);
        return false;
    }

    free(wire);
    uint32_t elapsed = millis() - startTime;
    Serial.println("DONE:" + String(totalChunks) + ":" + String(elapsed));
    // This confirms every chunk was ACKed at the link layer. Check the
    // slave's own serial output (RXDONE/RXPARTIAL/RXCRYPTOFAIL) for the
    // actual receive+decrypt outcome.
    return true;
}

void sendChunkedMessage(byte recipient, const String& message) {
    static byte sessionCounter = 0;
    sessionCounter++;
    selectBestRadio(message.length());
    // message.c_str()/.length() carry the exact byte sequence typed/sent --
    // no character filtering happens anywhere in this path, so letters,
    // digits, punctuation, symbols, and UTF-8 text all pass through as-is.
    sendChunkedBinary(recipient, (const uint8_t*)message.c_str(), message.length(),
                       sessionCounter, FT_TEXT, "");
}

// =================== serial command handling ===================

void checkSerialCommands(String& input) {
    if (input.equalsIgnoreCase("FORCE:SX")) {
        if (sx1278_ok) { overrideRadio=RADIO_SX1278; activeRadio=RADIO_SX1278; Serial.println("[OVERRIDE] Locked to SX1278."); }
        else Serial.println("[OVERRIDE] SX1278 not available.");
    } else if (input.equalsIgnoreCase("FORCE:RYLR")) {
        if (rylr_ok) { overrideRadio=RADIO_RYLR; activeRadio=RADIO_RYLR; Serial.println("[OVERRIDE] Locked to RYLR896."); }
        else Serial.println("[OVERRIDE] RYLR896 not available.");
    } else if (input.equalsIgnoreCase("FORCE:AUTO")) {
        overrideRadio=RADIO_NONE; selectBestRadio();
        Serial.println("[OVERRIDE] Auto. Active: " + String(radioName(activeRadio)));
    } else if (input.equalsIgnoreCase("STATUS")) {
        Serial.println("[STATUS] SX1278=" + String(sx1278_ok?"OK":"FAIL")
            + "  RYLR=" + String(rylr_ok?"OK":"FAIL")
            + "  Active=" + String(radioName(activeRadio))
            + "  ChunkSize=" + String(activeChunkSize())
            + "  FreeHeap=" + String(ESP.getFreeHeap())
            + "  FreePSRAM=" + String(ESP.getFreePsram())
            + "  Crypto=AES128-GCM");
    }
}

void handleSendFile(const String& cmdLine) {
    // format: SENDFILE:<nodeHex>:<size>:<type>:<filename>
    int idx[4]; int found = 0;
    for (int i = 0; i < (int)cmdLine.length() && found < 4; i++) {
        if (cmdLine[i] == ':') { idx[found++] = i; }
    }
    if (found < 4) { Serial.println("FAILED:0"); return; }

    String nodeStr = cmdLine.substring(idx[0] + 1, idx[1]);
    String sizeStr = cmdLine.substring(idx[1] + 1, idx[2]);
    String typeStr = cmdLine.substring(idx[2] + 1, idx[3]);
    String fname   = cmdLine.substring(idx[3] + 1);

    byte node = strtol(nodeStr.c_str(), NULL, 16);
    size_t fileSize = (size_t)sizeStr.toInt();
    FileType ftype = fileTypeFromString(typeStr);

    // See STATUS command's FreeHeap/FreePSRAM output to check headroom
    // on your specific board before pushing large transfers without
    // PSRAM fitted.
    // Ceiling raised to 1,000,000 (~1MB) to match the slave's raised
    // MAX_CHUNKS=4200. Be aware this is a LINK BUDGET warning, not a
    // memory one: a ~1MB transfer at ~4000 chunks with per-chunk ACK
    // round-trips (now with multi-pass retry) will realistically take
    // several minutes even on a clean link, and much longer if the
    // link is marginal.
    if (fileSize == 0 || fileSize > 1000000) {
        Serial.println("[TX] Rejected: size must be 1-1000000 bytes (got " + String(fileSize) + ")");
        Serial.println("FAILED:0");
        return;
    }

    uint8_t* buf = (uint8_t*)bigMalloc(fileSize);
    if (!buf) {
        Serial.println("[MEM] Could not allocate " + String(fileSize) + " bytes to receive from PC");
        Serial.println("FAILED:0");
        return;
    }

    size_t received = 0;
    uint32_t lastByteTime = millis();
    while (received < fileSize) {
        if (Serial.available()) {
            buf[received++] = Serial.read();
            lastByteTime = millis();
        } else if (millis() - lastByteTime > 8000) {
            Serial.println("FAILED:0");
            free(buf);
            return;
        }
    }

    Serial.println("RECEIVED_FROM_PC:" + String(received));

    static byte sessionCounter = 100;
    sessionCounter++;
    selectBestRadio(fileSize);
    Serial.println("[TX] Using " + String(radioName(activeRadio)) + " for this transfer (" + String(fileSize) + " bytes, type=" + typeStr + ")");
    sendChunkedBinary(node, buf, fileSize, sessionCounter, ftype, fname);
    free(buf);
}

// =================== setup/loop ===================

void setup() {
    Serial.begin(115200);
    cryptoInit();

    sx1278_ok = initSX1278();
    rylr_ok   = initRYLR();
    selectBestRadio();

    if (!sx1278_ok && !rylr_ok) {
        Serial.println("[FATAL] Both radios failed!");
        while (true) delay(1000);
    }

    Serial.println("LoRa Master Initialized (AES-128-GCM, adaptive radio, multi-pass retry)");
    Serial.println("FreeHeap=" + String(ESP.getFreeHeap()) + "  FreePSRAM=" + String(ESP.getFreePsram()));
    Serial.println("Use: NODE_ID MESSAGE | SENDFILE:NODE_ID:size:type:filename | FORCE:SX | FORCE:RYLR | FORCE:AUTO | STATUS");
}

void loop() {
    if (Serial.available()) {
        String input = Serial.readStringUntil('\n');
        input.trim();
        if (input.length() > 0) {
            if (input.startsWith("SENDFILE:")) {
                handleSendFile(input);
            } else if (input.startsWith("FORCE:") || input.equalsIgnoreCase("STATUS")) {
                checkSerialCommands(input);
            } else {
                int spaceIndex = input.indexOf(' ');
                if (spaceIndex != -1) {
                    String nodeStr = input.substring(0, spaceIndex);
                    String message = input.substring(spaceIndex + 1);
                    byte nodeAddress = strtol(nodeStr.c_str(), NULL, 16);
                    sendChunkedMessage(nodeAddress, message);
                } else {
                    Serial.println("Invalid format! Use: NODE_ID MESSAGE");
                }
            }
        }
    }
}
