/*
  LoRa SLAVE — dual radio (SX1278 + RYLR896) with failover
  AES-128-GCM decryption, partial-decrypt recovery, multi-file-type
  metadata, LCD status.

  ------------------------------------------------------------------
  FIX IN THIS VERSION: IDLE-BASED TIMEOUT (paired with the master's
  new multi-pass retry logic)
  ------------------------------------------------------------------
  The previous timeout was measured from the START of the session:

      if (millis() - t.startTime > 45000) ...

  That's 45 seconds total no matter what -- on a bigger file (more
  chunks, more retries needed on a marginal link) this could fire
  while the master was still actively and successfully sending, just
  because the whole transfer legitimately takes longer than 45s. This
  produced "partial recovery" results even on transfers that would
  have finished fine given more time.

  Fix: the timeout is now measured from the LAST CHUNK RECEIVED (idle
  time), not from session start. As long as chunks keep arriving --
  even slowly, even with the master's retry passes kicking in -- the
  session stays alive. It only gives up after a genuine period of
  silence, which means the link is actually stuck/gone.
  ------------------------------------------------------------------
  EARLIER FIX (still in place): MEMORY / RELIABILITY AT 100-300KB
  ------------------------------------------------------------------
  One buffer sized for the whole transfer is allocated up front; each
  incoming chunk is written directly to its correct byte offset
  (offset = chunkIndex * assumedChunkSize). No per-chunk allocations,
  no reassembly copy. Decryption happens IN PLACE in that same buffer.
  Peak RAM is ~1x file size, matching the master.
  ------------------------------------------------------------------
  OTHER
  ------------------------------------------------------------------
  - File types: TEXT, PNG, JPG, PDF, DOCX, PPTX, OTHER.
  - If the transfer stalls, does a best-effort in-place decrypt on
    whatever arrived (AES-GCM's CTR core means received bytes decode
    correctly per-block even without the rest) and reports PARTIAL
    instead of discarding everything. With the master's multi-pass
    retry now covering chunk 0 (the metadata chunk) just like any
    other chunk, this should rarely be needed in practice.
  ------------------------------------------------------------------

  LCD wiring (PCF8574 I2C backpack, 16x2): SDA->GPIO4, SCL->GPIO5.
  If blank, try address 0x3F instead of 0x27 below.
*/

#include <SPI.h>
#include <LoRa.h>
#include <HardwareSerial.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include "mbedtls/base64.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"
#include "esp_heap_caps.h"

const int csPin    = 10;
const int resetPin =  9;
const int irqPin   =  8;

#define RYLR_RX_PIN  18
#define RYLR_TX_PIN  17
#define RYLR_BAUD    115200
HardwareSerial rylrSerial(1);

#define LCD_SDA 4
#define LCD_SCL 5
#define LCD_ADDR 0x27
LiquidCrystal_I2C lcd(LCD_ADDR, 16, 2);

typedef enum { RADIO_NONE=0, RADIO_SX1278=1, RADIO_RYLR=2 } RadioID;
RadioID activeRadio   = RADIO_NONE;
RadioID overrideRadio = RADIO_NONE;
bool    sx1278_ok     = false;
bool    rylr_ok       = false;

// Declared here (not further down) so the Arduino IDE's auto-generated
// prototypes -- inserted at the very top of the file -- can see this
// type; otherwise you get "'RxEvent' was not declared in this scope".
struct RxEvent {
    enum { NONE, CHUNK, TEXT } kind = NONE;
    byte sender=0, sessionId=0; uint16_t totalChunks=0, chunkIndex=0; byte chunkLen=0;
    uint8_t rawPayload[260]; String b64Payload; bool isB64=false;
    String text; int rssi=0; RadioID fromRadio=RADIO_NONE;
};

#define SPREADING_FACTOR 7
#define SX_CHUNK_MAGIC 0xC5

const byte nodeAddress   = 0x02;
const byte masterAddress = 0xAB;
const int  syncWord      = 0x23;

#define CHUNK_SX1278 240
#define CHUNK_RYLR   128
#define RYLR_RAW_PER_CHUNK 96   // 128 base64 chars -> exactly 96 raw bytes for a full chunk

// How long we tolerate silence (no new chunk arriving) before we give
// up on a session and attempt best-effort partial recovery. This is
// NOT a total-transfer-time cap -- a slow-but-progressing transfer
// (e.g. master doing multiple retry passes on a marginal link) will
// keep resetting this clock every time a chunk lands, however long
// the overall transfer ends up taking.
#define IDLE_TIMEOUT_MS 20000

// =================== memory helper ===================
void* bigMalloc(size_t n) {
    void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (p) return p;
    return malloc(n);
}

// =================== AES-128-GCM CRYPTO ===================
static const char* CRYPTO_PASSPHRASE = "LAUDENBHOJYAM12"; // MUST match master

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

// Full verified in-place decrypt. buf = nonce(12) || tag(16) || ciphertext.
// Ciphertext is decrypted IN PLACE (becomes plaintext at the same offset).
bool cryptoDecryptVerifyInPlace(uint8_t* buf, size_t bufLen, size_t* outPlainLen) {
    if (bufLen < (GCM_NONCE_BYTES + GCM_TAG_BYTES)) return false;
    uint8_t* nonce = buf;
    uint8_t* tag   = buf + GCM_NONCE_BYTES;
    uint8_t* cipher = buf + GCM_NONCE_BYTES + GCM_TAG_BYTES;
    size_t cipherLen = bufLen - GCM_NONCE_BYTES - GCM_TAG_BYTES;
    int rc = mbedtls_gcm_auth_decrypt(&g_gcm, cipherLen, nonce, GCM_NONCE_BYTES, NULL, 0,
                                       tag, GCM_TAG_BYTES, cipher, cipher);
    if (rc != 0) return false;
    *outPlainLen = cipherLen;
    return true;
}

// Best-effort in-place decrypt WITHOUT tag verification, for partial
// transfers. AES-GCM ciphers via AES-CTR internally: decrypting block N
// only needs the nonce + block counter N, so bytes we DID receive
// decrypt correctly even with other chunks missing/zeroed.
bool cryptoDecryptBestEffortInPlace(uint8_t* buf, size_t bufLen) {
    if (bufLen < (GCM_NONCE_BYTES + GCM_TAG_BYTES)) return false;
    uint8_t* nonce = buf;
    uint8_t* cipher = buf + GCM_NONCE_BYTES + GCM_TAG_BYTES;
    size_t cipherLen = bufLen - GCM_NONCE_BYTES - GCM_TAG_BYTES;

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_enc(&aes, g_aesKey, AES_KEY_BYTES * 8) != 0) {
        mbedtls_aes_free(&aes);
        return false;
    }
    uint8_t counterBlock[16];
    memcpy(counterBlock, nonce, 12);
    counterBlock[12] = 0; counterBlock[13] = 0; counterBlock[14] = 0; counterBlock[15] = 1;

    size_t offset = 0;
    uint8_t streamBlock[16];
    mbedtls_aes_crypt_ctr(&aes, cipherLen, &offset, counterBlock, streamBlock, cipher, cipher);
    mbedtls_aes_free(&aes);
    return true;
}

// =================== RSSI -> distance ===================
const float RSSI_AT_1M         = -40.0;
const float PATH_LOSS_EXPONENT = 2.5;
float rssiToDistance(int rssi) { return pow(10.0, (RSSI_AT_1M - rssi) / (10.0 * PATH_LOSS_EXPONENT)); }

// =================== transfer state (single pre-allocated buffer) ===================
#define MAX_CHUNKS 4200   // supports up to ~1MB at 240 bytes/chunk on SX1278
struct Transfer {
    byte sessionId = 0;
    uint16_t totalChunks = 0;
    bool received[MAX_CHUNKS] = {false};
    uint16_t receivedCount = 0;
    bool active = false;
    bool usesB64 = false;
    uint32_t startTime = 0;
    uint32_t lastChunkTime = 0;   // NEW: updated every time a chunk lands; drives the idle timeout
    int lastRssi = 0;
    uint8_t* buf = NULL;          // single reconstruction buffer for this session
    size_t   bufCapacity = 0;     // allocated size
    size_t   assumedChunkRaw = 0; // raw bytes per full (non-last) chunk at this buf's offsets
    uint16_t lastChunkLen = 0;    // actual raw length of the final chunk once it's arrived
    bool     gotLastChunk = false;
};
Transfer t;

void lcdShow(const String& line1, const String& line2) {
    lcd.setCursor(0,0); lcd.print("                ");
    lcd.setCursor(0,0); lcd.print(line1.substring(0, 16));
    lcd.setCursor(0,1); lcd.print("                ");
    lcd.setCursor(0,1); lcd.print(line2.substring(0, 16));
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
    Serial.println("[SX1278] Init OK");
    return true;
}

bool initRYLR() {
    rylrSerial.begin(RYLR_BAUD, SERIAL_8N1, RYLR_RX_PIN, RYLR_TX_PIN);
    delay(400);
    while (rylrSerial.available()) rylrSerial.read();
    auto atCmd = [&](const String& cmd) -> bool {
        rylrSerial.println(cmd);
        uint32_t t0 = millis(); String resp = "";
        while (millis() - t0 < 1500) {
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
    ok &= atCmd("AT+ADDRESS=2");
    ok &= atCmd("AT+NETWORKID=5");
    ok &= atCmd("AT+BAND=433000000");
    ok &= atCmd("AT+PARAMETER=10,7,1,7");
    ok &= atCmd("AT+CRFOP=15");
    Serial.println(ok ? "[RYLR896] Init OK" : "[RYLR896] Init FAILED");
    return ok;
}

void selectBestRadio() {
    if (overrideRadio != RADIO_NONE) { activeRadio = overrideRadio; return; }
    if (sx1278_ok)      activeRadio = RADIO_SX1278;
    else if (rylr_ok)   activeRadio = RADIO_RYLR;
    else                activeRadio = RADIO_NONE;
}

const char* radioName(RadioID r) {
    switch(r) { case RADIO_SX1278: return "SX"; case RADIO_RYLR: return "RY"; default: return "--"; }
}

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
            + "  FreeHeap=" + String(ESP.getFreeHeap())
            + "  FreePSRAM=" + String(ESP.getFreePsram())
            + "  Crypto=AES128-GCM");
    }
}

// =================== send helper (ACK only, works on either radio) ===================

void sendAck(byte recipient, RadioID viaRadio, uint16_t chunkIndex) {
    String text = "ACK:" + String(chunkIndex);
    if (viaRadio == RADIO_SX1278) {
        LoRa.beginPacket();
        LoRa.write(recipient);
        LoRa.write(nodeAddress);
        LoRa.print(text);
        LoRa.endPacket();
    } else if (viaRadio == RADIO_RYLR) {
        String cmd = "AT+SEND=" + String(recipient) + "," + String(text.length()) + "," + text;
        rylrSerial.println(cmd);
        uint32_t t0 = millis();
        while (millis() - t0 < 800) { if (rylrSerial.available()) rylrSerial.read(); }
    }
}

// =================== packet receive ===================

bool pollSX1278(RxEvent& ev) {
    int pktSize = LoRa.parsePacket();
    if (pktSize <= 0) return false;
    byte recipient = LoRa.read();
    if (recipient != nodeAddress || !LoRa.available()) return false;
    byte sender = LoRa.read();
    byte first = LoRa.peek();
    ev.rssi = LoRa.packetRssi();
    ev.fromRadio = RADIO_SX1278;
    ev.sender = sender;
    if (first == SX_CHUNK_MAGIC) {
        LoRa.read();
        ev.sessionId   = LoRa.read();
        ev.totalChunks = ((uint16_t)LoRa.read() << 8) | LoRa.read();
        ev.chunkIndex  = ((uint16_t)LoRa.read() << 8) | LoRa.read();
        ev.chunkLen    = LoRa.read();
        int n = 0;
        while (LoRa.available() && n < (int)sizeof(ev.rawPayload)) ev.rawPayload[n++] = LoRa.read();
        ev.isB64 = false;
        ev.kind = RxEvent::CHUNK;
    } else {
        String msg = "";
        while (LoRa.available()) msg += (char)LoRa.read();
        ev.text = msg;
        ev.kind = RxEvent::TEXT;
    }
    return true;
}

bool pollRYLR(RxEvent& ev) {
    static String rylrBuf = "";
    if (!rylr_ok || !rylrSerial.available()) return false;
    while (rylrSerial.available()) {
        char c = rylrSerial.read();
        if (c == '\n') {
            rylrBuf.trim();
            if (!rylrBuf.startsWith("+RCV=")) { rylrBuf = ""; continue; }
            int c2 = rylrBuf.indexOf(',');
            int c3 = rylrBuf.indexOf(',', c2 + 1);
            int c4 = rylrBuf.lastIndexOf(',');
            int c5 = rylrBuf.lastIndexOf(',', c4 - 1);
            if (c3 < 0 || c5 < 0 || c5 <= c3) { rylrBuf = ""; continue; }
            String data = rylrBuf.substring(c3 + 1, c5);
            String rssiStr = rylrBuf.substring(c5 + 1, c4);
            ev.rssi = rssiStr.toInt();
            ev.fromRadio = RADIO_RYLR;

            int f[5]; String remaining = data; bool headerOk = true;
            for (int i = 0; i < 5; i++) {
                int comma = remaining.indexOf(',');
                if (comma < 0) { headerOk = false; break; }
                f[i] = strtol(remaining.substring(0, comma).c_str(), NULL, 16);
                remaining = remaining.substring(comma + 1);
            }
            if (headerOk && f[0] == nodeAddress) {
                ev.sessionId   = (byte)f[1];
                ev.totalChunks = (uint16_t)f[2];
                ev.chunkIndex  = (uint16_t)f[3];
                ev.chunkLen    = (byte)f[4];
                ev.b64Payload  = remaining;
                ev.isB64 = true;
                ev.kind = RxEvent::CHUNK;
            } else {
                ev.text = data;
                ev.kind = RxEvent::TEXT;
            }
            rylrBuf = "";
            return true;
        } else if (c != '\r') rylrBuf += c;
    }
    return false;
}

// =================== transfer handling ===================

void resetTransfer() {
    if (t.buf) { free(t.buf); t.buf = NULL; }
    for (int i = 0; i < MAX_CHUNKS; i++) t.received[i] = false;
    t.active = false; t.totalChunks = 0; t.receivedCount = 0;
    t.bufCapacity = 0; t.assumedChunkRaw = 0; t.lastChunkLen = 0; t.gotLastChunk = false;
    t.lastChunkTime = 0;
}

void finalizeTransfer(bool forcePartial) {
    float totalElapsedSec = (millis() - t.startTime) / 1000.0;
    bool decryptOk = false, isPartial = false;
    size_t plainLen = 0;

    // Actual reconstructed length: all-but-last chunks are exactly
    // assumedChunkRaw bytes; the last chunk's real length is tracked
    // separately since it's usually shorter.
    size_t bufLen = 0;
    if (t.totalChunks > 0) {
        size_t lastLen = t.gotLastChunk ? t.lastChunkLen : t.assumedChunkRaw;
        bufLen = (size_t)(t.totalChunks - 1) * t.assumedChunkRaw + lastLen;
        if (bufLen > t.bufCapacity) bufLen = t.bufCapacity; // safety clamp
    }

    if (t.buf && bufLen > (GCM_NONCE_BYTES + GCM_TAG_BYTES)) {
        if (!forcePartial) {
            decryptOk = cryptoDecryptVerifyInPlace(t.buf, bufLen, &plainLen);
        }
        if (!decryptOk) {
            if (cryptoDecryptBestEffortInPlace(t.buf, bufLen)) {
                plainLen = bufLen - GCM_NONCE_BYTES - GCM_TAG_BYTES;
                isPartial = true;
                decryptOk = true;
            }
        }
    }

    if (decryptOk && plainLen > 2) {
        uint8_t* plain = t.buf + GCM_NONCE_BYTES + GCM_TAG_BYTES; // in-place: plaintext now lives here
        uint8_t ftype = plain[0];
        uint8_t fnameLen = plain[1];
        String fname = "";
        for (int i = 0; i < fnameLen && (2 + i) < (int)plainLen; i++) fname += (char)plain[2 + i];
        size_t dataOff = 2 + fnameLen;
        size_t dataLen = (plainLen > dataOff) ? (plainLen - dataOff) : 0;

        // Sanity-check the metadata before trusting it. If chunk 0 was
        // never received (best-effort path with a hole at the start),
        // ftype/fnameLen/fname will be garbage -- flag it clearly rather
        // than silently handing a bogus name/type to the PC-side GUI.
        bool metaLooksSane = (ftype <= 6) && (fnameLen <= 200) &&
                              (!t.received[0] ? false : true);
        if (!metaLooksSane) {
            Serial.println("[RX] WARNING: chunk 0 (metadata) missing or metadata invalid -- "
                            "type/filename below may be garbage");
        }

        Serial.println("RXMETA:" + String(ftype) + ":" + fname + ":" + String(dataLen));
        Serial.println("RXFILE_START:" + String(dataLen));
        if (dataLen > 0) Serial.write(plain + dataOff, dataLen);
        Serial.println();
        Serial.println("RXFILE_END");

        Serial.println((isPartial ? "RXPARTIAL:" : "RXDONE:") + String(t.receivedCount) + ":" + String(t.totalChunks) +
                        ":" + String(totalElapsedSec, 2) + ":" + String(t.lastRssi) +
                        ":" + String(rssiToDistance(t.lastRssi), 1));

        lcdShow(isPartial ? "Partial Recover" : "Recv+Decrypt OK",
                "~" + String((int)rssiToDistance(t.lastRssi)) + "m " + String(totalElapsedSec, 1) + "s");
    } else {
        Serial.println("RXCRYPTOFAIL:" + String(t.totalChunks));
        lcdShow("DECRYPT FAIL", "~" + String((int)rssiToDistance(t.lastRssi)) + "m " + String(totalElapsedSec, 1) + "s");
    }

    resetTransfer();
}

void handleChunkEvent(RxEvent& ev) {
    if (ev.totalChunks == 0 || ev.totalChunks > MAX_CHUNKS) return;

    if (!t.active || t.sessionId != ev.sessionId) {
        resetTransfer();
        t.active = true;
        t.sessionId = ev.sessionId;
        t.totalChunks = ev.totalChunks;
        t.startTime = millis();
        t.lastChunkTime = millis();
        t.usesB64 = ev.isB64;
        t.assumedChunkRaw = ev.isB64 ? RYLR_RAW_PER_CHUNK : CHUNK_SX1278;

        t.bufCapacity = (size_t)t.totalChunks * t.assumedChunkRaw;
        t.buf = (uint8_t*)bigMalloc(t.bufCapacity);
        if (!t.buf) {
            Serial.println("[MEM] Failed to allocate " + String(t.bufCapacity) +
                            " bytes for incoming transfer -- dropping session");
            t.active = false;
            return;
        }
    }
    if (!t.active || !t.buf) return; // session alloc failed earlier; ignore further chunks
    t.lastRssi = ev.rssi;

    if (ev.chunkIndex < MAX_CHUNKS && !t.received[ev.chunkIndex]) {
        size_t offset = (size_t)ev.chunkIndex * t.assumedChunkRaw;

        if (ev.isB64) {
            size_t maxOut = 0;
            mbedtls_base64_decode(NULL, 0, &maxOut, (const unsigned char*)ev.b64Payload.c_str(), ev.b64Payload.length());
            if (offset + maxOut <= t.bufCapacity) {
                size_t actualOut = 0;
                mbedtls_base64_decode(t.buf + offset, maxOut, &actualOut,
                                       (const unsigned char*)ev.b64Payload.c_str(), ev.b64Payload.length());
                if (ev.chunkIndex == t.totalChunks - 1) { t.lastChunkLen = actualOut; t.gotLastChunk = true; }
            }
        } else {
            if (offset + ev.chunkLen <= t.bufCapacity) {
                memcpy(t.buf + offset, ev.rawPayload, ev.chunkLen);
                if (ev.chunkIndex == t.totalChunks - 1) { t.lastChunkLen = ev.chunkLen; t.gotLastChunk = true; }
            }
        }

        t.received[ev.chunkIndex] = true;
        t.receivedCount++;
        t.lastChunkTime = millis();   // NEW: reset the idle clock on every new chunk
    }

    sendAck(ev.sender, ev.fromRadio, ev.chunkIndex);

    float dist = rssiToDistance(ev.rssi);
    Serial.println("[RX] chunk " + String(ev.chunkIndex) + "/" + String(ev.totalChunks) +
                    " rssi=" + String(ev.rssi) + " dist~" + String(dist, 1) + "m");

    if (t.receivedCount == t.totalChunks) {
        finalizeTransfer(false);
    }
}

void handleTextEvent(RxEvent& ev) {
    // No slave-side control protocol beyond ACK (which is master-bound);
    // nothing for the slave to act on here currently.
}

// =================== timeout watchdog (idle-based) ===================

void checkTransferTimeout() {
    if (!t.active || t.receivedCount >= t.totalChunks) return;

    uint32_t reference = t.lastChunkTime ? t.lastChunkTime : t.startTime;
    uint32_t idleFor = millis() - reference;

    if (idleFor > IDLE_TIMEOUT_MS) {
        if (t.receivedCount > 0 && t.buf) {
            Serial.println("[RX] " + String(idleFor / 1000) + "s of silence with " +
                            String(t.receivedCount) + "/" + String(t.totalChunks) +
                            " chunks -- attempting best-effort partial recovery");
            finalizeTransfer(true);
        } else {
            lcdShow("FAILED 0/" + String(t.totalChunks), "no data");
            Serial.println("RXFAILED:0:" + String(t.totalChunks));
            resetTransfer();
        }
    }
}

// =================== setup/loop ===================

void setup() {
    Serial.begin(115200);
    cryptoInit();

    Wire.begin(LCD_SDA, LCD_SCL);
    lcd.init();
    lcd.backlight();
    lcd.setCursor(0,0); lcd.print("LoRa Slave Init");

    sx1278_ok = initSX1278();
    rylr_ok   = initRYLR();
    selectBestRadio();

    if (!sx1278_ok && !rylr_ok) {
        Serial.println("[FATAL] Both radios failed!");
        lcdShow("RADIO INIT FAIL", "Check wiring");
        while (true) delay(1000);
    }

    Serial.println("LoRa Slave Initialized (AES-128-GCM, single-buffer reconstruction, idle-based timeout)");
    Serial.println("FreeHeap=" + String(ESP.getFreeHeap()) + "  FreePSRAM=" + String(ESP.getFreePsram()));
    lcdShow("Waiting...", String(radioName(activeRadio)) + " ready");
}

void loop() {
    if (Serial.available()) {
        String input = Serial.readStringUntil('\n');
        input.trim();
        if (input.length() > 0 && (input.startsWith("FORCE:") || input.equalsIgnoreCase("STATUS"))) {
            checkSerialCommands(input);
        }
    }

    RxEvent ev;
    if (sx1278_ok && pollSX1278(ev)) {
        if (ev.kind == RxEvent::CHUNK) handleChunkEvent(ev);
        else if (ev.kind == RxEvent::TEXT) handleTextEvent(ev);
    }
    RxEvent ev2;
    if (rylr_ok && pollRYLR(ev2)) {
        if (ev2.kind == RxEvent::CHUNK) handleChunkEvent(ev2);
        else if (ev2.kind == RxEvent::TEXT) handleTextEvent(ev2);
    }

    checkTransferTimeout();
}
