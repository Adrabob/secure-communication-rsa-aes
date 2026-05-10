# Secure Communication Simulator — RSA + AES Hybrid Encryption

A command-line application that simulates a secure end-to-end communication channel between two parties using a **hybrid cryptographic protocol**. The project demonstrates RSA key exchange, AES symmetric encryption in two modes (GCM and CTR), digital signatures, and a Man-in-the-Middle (MitM) attack scenario to highlight the difference in integrity guarantees between the two AES modes.

---

## Project Purpose

This project was built as a Computer Security assignment to explore and compare core cryptographic primitives in a practical, interactive setting:

- **Confidentiality** — RSA-OAEP encrypts the AES session key; AES encrypts the message payload.
- **Authentication** — RSA digital signatures (PKCS#1 v1.5 + SHA-256) verify the sender's identity before any session key is accepted.
- **Integrity** — AES-GCM provides authenticated encryption (MAC tag); AES-CTR provides encryption only, which makes it vulnerable to undetected tampering.
- **MitM Simulation** — The interactive challenge step flips a byte in the ciphertext mid-transmission to demonstrate how GCM detects corruption while CTR silently produces garbled or modified output.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.8+ |
| Cryptography | [PyCryptodome](https://pycryptodome.readthedocs.io/) |
| Asymmetric encryption | RSA-2048 with OAEP padding |
| Symmetric encryption | AES-128 (GCM and CTR modes) |
| Digital signature | PKCS#1 v1.5 with SHA-256 |
| Key generation | OS-level CSPRNG via `Crypto.Random` |

---

## Architecture

```
main.py          — Entry point; orchestrates the demo flow and user interaction
user.py          — User class encapsulating key pairs, session key, and send/receive logic
rsa_aes_utils.py — Pure cryptographic utility functions (RSA, AES, signing, verification)
```

### Protocol Flow

```
Alice                                          Bob
  |                                              |
  |-- generate RSA key pair                      |-- generate RSA key pair
  |                                              |
  |-- generate AES session key                   |
  |-- encrypt session key with Bob's public key  |
  |-- sign encrypted packet with Alice's priv key|
  |                                              |
  |-------- [encrypted key + signature] -------->|
  |                                              |-- verify Alice's signature
  |                                              |-- decrypt session key with Bob's priv key
  |                                              |
  |<======= SECURE CHANNEL ESTABLISHED ========>|
  |                                              |
  |-- encrypt message with shared AES key        |
  |-------- [ciphertext + nonce (+ tag)] ------->|
                    [optional MitM byte flip]
                                                 |-- decrypt (GCM: verify tag / CTR: no check)
```

---

## Setup

### Prerequisites

- Python 3.8 or higher
- pip

### Install Dependencies

```bash
pip install pycryptodome
```

### Run

```bash
python main.py
```

---

## Usage

1. The program automatically generates RSA-2048 key pairs for **Alice** and **Bob**.
2. Alice creates a 128-bit AES session key, encrypts it with Bob's public key, and signs the packet.
3. Bob verifies the signature and decrypts the session key — the secure channel is established.
4. You are prompted to select an AES mode (**GCM** or **CTR**) and enter a message.
5. Optionally corrupt the packet in transit to observe how each mode responds:
   - **AES-GCM** — raises a MAC verification failure and rejects the message.
   - **AES-CTR** — decrypts to garbled output with no error, illustrating the lack of integrity protection.
6. Press `Q` to exit.

---

## Key Concepts Demonstrated

| Concept | Implementation |
|---|---|
| Hybrid encryption | RSA wraps AES key; AES encrypts bulk data |
| Authenticated encryption | AES-GCM produces a 128-bit authentication tag |
| Unauthenticated encryption | AES-CTR — no tag, no integrity check |
| Non-repudiation | RSA signature on the encrypted key packet |
| Replay / tampering detection | GCM tag verification fails on any modification |

---

## License

This project is intended for educational purposes.
