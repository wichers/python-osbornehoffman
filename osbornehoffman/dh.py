"""Diffie-Hellman key exchange for OH V4 protocol.

Uses RFC 3526 Group 14 (2048-bit MODP) parameters and pycryptodome
for random number generation and ASN.1 encoding.
"""

from __future__ import annotations

import asyncio
import logging
import struct

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.asn1 import DerInteger, DerSequence

_LOGGER = logging.getLogger(__name__)

# RFC 3526 Group 14: 2048-bit MODP Group
# https://www.rfc-editor.org/rfc/rfc3526#section-3
_DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_DH_G = 2


def _encode_dh_params(p: int, g: int) -> bytes:
    """Encode DH parameters as ASN.1 DER sequence (DHParameter)."""
    seq = DerSequence([p, g, 0])
    return seq.encode()


def _decode_length_prefixed(data: bytes) -> tuple[bytes, int]:
    """Read a 2-byte big-endian length prefix and return (payload, total_consumed)."""
    if len(data) < 2:
        raise ValueError("Not enough data for length prefix")
    length = struct.unpack(">H", data[:2])[0]
    if len(data) < 2 + length:
        raise ValueError(f"Expected {length} bytes, got {len(data) - 2}")
    return data[2 : 2 + length], 2 + length


def _encode_length_prefixed(data: bytes) -> bytes:
    """Encode data with a 2-byte big-endian length prefix."""
    return struct.pack(">H", len(data)) + data


class OHDiffieHellman:
    """Server-side Diffie-Hellman key exchange for OH V4 protocol."""

    def __init__(self) -> None:
        """Initialize DH parameters and generate keypair."""
        self._p = _DH_P
        self._g = _DH_G

        # Generate private key: random integer in [2, p-2]
        # Use 256 bytes of randomness for a 2048-bit group
        rand_bytes = get_random_bytes(256)
        self._private_key = int.from_bytes(rand_bytes, "big") % (self._p - 3) + 2

        # Compute public key: g^private mod p
        self._public_key = pow(self._g, self._private_key, self._p)

        self._shared_secret: bytes | None = None
        self._aes_key: bytes | None = None

    @property
    def public_params_encoded(self) -> bytes:
        """Return ASN.1 DER encoded DH parameters, length-prefixed."""
        params = _encode_dh_params(self._p, self._g)
        return _encode_length_prefixed(params)

    @property
    def public_key_encoded(self) -> bytes:
        """Return public key bytes, length-prefixed.

        Strips leading 0x00 sign byte if present (matching Java BigInteger behavior).
        """
        key_bytes = self._public_key.to_bytes(
            (self._public_key.bit_length() + 7) // 8, "big"
        )
        # Strip leading zero if present (Java BigInteger sign byte)
        if key_bytes[0] == 0x00 and len(key_bytes) > 256:
            key_bytes = key_bytes[1:]
        return _encode_length_prefixed(key_bytes)

    def compute_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """Compute shared secret from peer's public key.

        Returns the derived 32-byte AES-256 key.
        """
        # Handle leading 0x00 sign byte (Java BigInteger convention)
        peer_public_key = int.from_bytes(peer_public_key_bytes, "big")

        if peer_public_key <= 1 or peer_public_key >= self._p - 1:
            raise ValueError("Invalid peer public key")

        # Compute shared secret: peer_public^private mod p
        shared_int = pow(peer_public_key, self._private_key, self._p)
        self._shared_secret = shared_int.to_bytes(
            (shared_int.bit_length() + 7) // 8, "big"
        )

        # Extract first 32 bytes as AES-256 key
        if len(self._shared_secret) < 32:
            raise ValueError("Shared secret too short for AES-256 key derivation")
        self._aes_key = self._shared_secret[:32]
        return self._aes_key

    @property
    def aes_key(self) -> bytes | None:
        """Return the derived AES key, or None if not yet negotiated."""
        return self._aes_key


async def negotiate_dh(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> bytes | None:
    """Perform server-side DH key exchange with a panel.

    Protocol:
        1. Server sends DH parameters (ASN.1 DER, length-prefixed)
        2. Server reads panel's public key (length-prefixed)
        3. Server sends its public key (length-prefixed)
        4. Panel sends AES-encrypted ACK to confirm

    Returns the derived 32-byte AES key, or None on failure.
    """
    dh = OHDiffieHellman()

    # Step 1: Send DH parameters
    _LOGGER.debug("DH: Sending public parameters")
    writer.write(dh.public_params_encoded)
    await writer.drain()

    # Step 2: Read panel's public key
    _LOGGER.debug("DH: Reading panel public key")
    try:
        length_header = await asyncio.wait_for(reader.readexactly(2), timeout=30)
        key_length = struct.unpack(">H", length_header)[0]
        if not 256 <= key_length <= 257:
            _LOGGER.warning("DH: Invalid panel key length: %d", key_length)
            return None
        panel_key_bytes = await asyncio.wait_for(
            reader.readexactly(key_length), timeout=30
        )
    except (asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
        _LOGGER.warning("DH: Failed to read panel public key: %s", exc)
        return None

    # Step 3: Send server's public key
    _LOGGER.debug("DH: Sending server public key")
    writer.write(dh.public_key_encoded)
    await writer.drain()

    # Compute shared secret and derive AES key
    try:
        aes_key = dh.compute_shared_secret(panel_key_bytes)
    except ValueError as exc:
        _LOGGER.warning("DH: Failed to compute shared secret: %s", exc)
        return None

    # Step 4: Read and validate encrypted ACK from panel
    _LOGGER.debug("DH: Waiting for encrypted ACK")
    try:
        encrypted_ack = await asyncio.wait_for(reader.readexactly(16), timeout=30)
        cipher = AES.new(aes_key, AES.MODE_ECB)
        ack = cipher.decrypt(encrypted_ack)
        if not ack[:4] == b"ACK\r":
            _LOGGER.warning("DH: Invalid ACK from panel: %s", ack)
            return None
    except (asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
        _LOGGER.warning("DH: Failed to read ACK: %s", exc)
        return None

    _LOGGER.info("DH: Key exchange completed successfully")
    return aes_key
