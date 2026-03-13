"""SRTP wrapper — documentation module.

aiortc handles SRTP internally as part of the DTLS-SRTP negotiation.
This module exists for documentation and potential future extension
(e.g., if we want to add custom SRTP profiles or manipulate packets
at the SRTP level).

How SRTP works in our stack:
  1. DTLS handshake establishes shared keys between peers
  2. SRTP uses those keys to encrypt/authenticate each RTP packet
  3. The encryption is transparent — our code sends RTP payloads,
     aiortc encrypts them before putting them on the wire
  4. A DPI inspector sees SRTP packets (standard, expected for WebRTC)

Our additional E2E crypto pipeline encrypts the DATA INSIDE the RTP
payload, so even if SRTP were compromised (e.g., via a TURN server
that terminates DTLS), the actual content remains protected.

Security layers (from inner to outer):
  1. Our E2E crypto pipeline (AES-GCM → ChaCha20 → etc.)
  2. SCTP over DTLS (DataChannel encryption)
  3. SRTP (media track encryption)

An attacker would need to break all three layers to read the data.
"""

# This module is intentionally minimal — aiortc handles the heavy lifting.
# Future extensions could include:
#   - Custom SRTP profiles
#   - Key rotation
#   - Packet-level inspection/logging for debugging
