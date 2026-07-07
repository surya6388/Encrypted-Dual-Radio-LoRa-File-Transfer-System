# Encrypted Dual-Radio LoRa File Transfer System

This repository contains the embedded firmware and Python graphical interfaces (GUIs) for a robust, AES-encrypted, dual-radio LoRa communication network. It supports the transmission of plain text, images, and raw documents (PDF, DOCX, XLSX, etc.) over long distances.

## System Architecture

The project is split into two primary components: the Master (Sender) and the Slave (Receiver). Each node requires an ESP32 wired to both an SX1278 (SPI) and an RYLR896 (UART) LoRa module. 

### Firmware Features
* **Dual-Radio Failover & Adaptive Selection**: Automatically selects the optimal radio based on payload size, preferring the SX1278 for payloads over 400 bytes, while retaining manual override capabilities (`FORCE:SX`, `FORCE:RYLR`).
* **AES-128-GCM Encryption**: Implements secure, hardware-accelerated in-place encryption and decryption using `mbedtls`. The encryption keys never cross the USB serial link.
* **Multi-Pass Selective Retry**: The Master firmware utilizes a sophisticated retry algorithm that makes multiple passes over unacknowledged chunks, ensuring large files are reliably transmitted without restarting the entire transfer on a single dropped packet.
* **Best-Effort Partial Recovery**: The Slave firmware employs an idle-based timeout to detect stalled transfers. If a transfer fails, AES-CTR underlying GCM allows the receiver to decrypt the surviving chunks, rescuing partial files instead of discarding all data.

### Python GUI Tools
* **Master GUI (`lora_gui.py`)**: Provides a visual interface to send files and text. It includes dynamic image processing, allowing users to send exact lossless files or apply on-the-fly resizing, grayscale conversion, and JPEG compression to save LoRa airtime.
* **Slave GUI (`lora_slave_gui.py`)**: Connects to the receiver node to reconstruct byte-streams. It decodes the incoming metadata, provides inline image previews (if applicable), and automatically saves arriving documents (e.g., `.pdf`, `.docx`) to a local `received_files` directory with their correct extensions.

## Hardware Configuration

| Module | Interface | ESP32 Pins (Master & Slave) |
| :--- | :--- | :--- |
| **SX1278** | SPI | SCK: 12, MISO: 13, MOSI: 11, CS: 10, RST: 9, DIO0: 8 |
| **RYLR896** | UART | RXD: 18, TXD: 17 (115200 Baud) |
| **LCD (Slave)** | I2C | SDA: 4, SCL: 5 (PCF8574 Backpack) |

## Getting Started

### 1. Flash the Firmware
* Upload `LoRa_Master.ino` to the sender ESP32.
* Upload `LoRa_Slave.ino` to the receiver ESP32.

### 2. Install Python Dependencies
Ensure you have Python installed, then install the required libraries for the GUIs:
`pip install pyserial pillow --break-system-packages`
*(Note: `pillow` is required for image previews and compression features)*.

### 3. Run the GUIs
1. Connect both ESP32 boards to your computer.
2. Launch the Master interface to initiate transfers: `python lora_gui.py`
3. Launch the Slave interface to monitor and auto-save incoming files: `python lora_slave_gui.py`
