"""
Key agreement handshake — platform side (R4).

The platform handles incoming DH init messages and completes the handshake:
  1. Recv  iot/dh/init     <- {device_id, algorithm, public_key (hex)}
  2. Generate ephemeral key pair for the device's chosen algorithm
  3. Derive session_key
  4. Compute HMAC over transcript and send response
  5. Recv  iot/dh/finish   <- {device_id, hmac_transcript}
  6. Verify device HMAC (mutual authentication)
  7. Store session_key in session_keys dict: device_id -> session_key

"""

from __future__ import annotations

import json

import paho.mqtt.client as mqtt

from spea_lab_iot.key_agreement import KeyAgreement

TOPIC_DH_INIT = "iot/dh/init"
TOPIC_DH_RESPONSE = "iot/dh/response"
TOPIC_DH_FINISH = "iot/dh/finish"

SUPPORTED_ALGORITHMS = {"auth_dh", "ecdh_ephemeral"}


class DHPlatformHandler:
    """
    Handles the DH handshake on the platform side.

    State per device is kept in _pending: device_id -> {ka, our_pub, peer_pub}
    Once finish is verified, session_key is written to the shared session_keys dict.
    """

    def __init__(
        self,
        allowed_devices: dict[str, str],  # device_id -> pin
        session_keys: dict[
            str, bytes
        ],  # device_id -> session_key (shared with platform)
        auth_keys: dict[str, bytes],  # device_id -> auth_key (for R5 AES-CBC-HMAC)
        log: callable = print,
    ) -> None:
        self._allowed = allowed_devices
        self._session_keys = session_keys
        self._auth_keys = auth_keys
        self._log = log
        # pending handshakes: device_id -> {ka, our_pub, peer_pub}
        self._pending: dict[str, dict] = {}

    # 1. Receive DH init from device
    def on_dh_init(self, client: mqtt.Client, msg: mqtt.MQTTMessage) -> None:
        try:
            payload = json.loads(msg.payload.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._log("Invalid JSON on dh/init")
            return

        device_id = payload.get("device_id")
        algorithm = payload.get("algorithm")
        peer_pub_hex = payload.get("public_key")

        if not device_id or not algorithm or not peer_pub_hex:
            self._log(f"Incomplete dh/init from {device_id!r}")
            return

        # Only enrolled devices can do key agreement
        pin = self._allowed.get(device_id)
        if pin is None:
            self._log(f"DH init rejected: unknown device_id={device_id!r}")
            return

        if algorithm not in SUPPORTED_ALGORITHMS:
            self._log(f"DH init rejected: unsupported algorithm={algorithm!r}")
            return

        peer_pub = bytes.fromhex(peer_pub_hex)

        # 2. Generate our ephemeral key pair
        ka = KeyAgreement.create(algorithm, pin)
        our_pub = ka.public_key_bytes()

        # 3. Derive session key
        try:
            session_key = ka.derive_session_key(peer_pub)
        except ValueError as e:
            self._log(f"DH key derivation error for {device_id!r}: {e}")
            return

        # 4. Compute HMAC and send response
        transcript_parts = [device_id.encode(), peer_pub, our_pub]
        hmac_hex = ka.make_transcript_hmac(transcript_parts)

        response = json.dumps(
            {
                "device_id": device_id,
                "public_key": our_pub.hex(),
                "hmac_transcript": hmac_hex,
            }
        )
        client.publish(TOPIC_DH_RESPONSE, response, qos=1)
        self._log(
            f"DH response sent to device_id={device_id!r} (algorithm={algorithm})"
        )

        # Save pending state to verify finish
        self._pending[device_id] = {
            "ka": ka,
            "our_pub": our_pub,
            "peer_pub": peer_pub,
            "session_key": session_key,
        }

    # 5. Receive DH finish from device
    def on_dh_finish(self, client: mqtt.Client, msg: mqtt.MQTTMessage) -> None:
        try:
            payload = json.loads(msg.payload.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._log("Invalid JSON on dh/finish")
            return

        device_id = payload.get("device_id")
        hmac_received = payload.get("hmac_transcript")

        if not device_id or not hmac_received:
            self._log(f"Incomplete dh/finish from {device_id!r}")
            return

        pending = self._pending.get(device_id)
        if pending is None:
            self._log(f"DH finish from unknown/unexpected device_id={device_id!r}")
            return

        ka: KeyAgreement = pending["ka"]
        our_pub: bytes = pending["our_pub"]
        peer_pub: bytes = pending["peer_pub"]

        # 6. Verify device HMAC (mutual authentication)
        finish_transcript = [device_id.encode(), our_pub, peer_pub]
        if not ka.verify_transcript_hmac(finish_transcript, hmac_received):
            self._log(
                f"DH finish HMAC invalid for device_id={device_id!r} — handshake rejected"
            )
            del self._pending[device_id]
            return

        # 7. Store session key
        session_key: bytes = pending["session_key"]
        self._session_keys[device_id] = session_key
        self._auth_keys[device_id] = ka.auth_key_bytes()
        del self._pending[device_id]

        self._log(
            f"Handshake complete for device_id={device_id!r} — "
            f"session_key={session_key.hex()[:16]}..."
        )
