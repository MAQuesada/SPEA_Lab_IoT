"""
Key agreement handshake — device side (R4).

Called after successful enrollment (R1).  Performs:
  1. Generate ephemeral key pair (auth_dh or ecdh_ephemeral)
  2. Send  iot/dh/init     -> {device_id, algorithm, public_key (hex)}
  3. Recv  iot/dh/response <- {device_id, public_key (hex), hmac_transcript}
  4. Verify platform HMAC (authentication — prevents MitM from broker)
  5. Derive session_key
  6. Send  iot/dh/finish   -> {device_id, hmac_transcript}
  7. Return session_key bytes to caller

Usage (inside device.py, after enrolled_event is set):
    from spea_lab_iot.dh_device import run_dh_handshake
    session_key = run_dh_handshake(client, sensor_id, pin, algorithm="ecdh_ephemeral")
"""

from __future__ import annotations

import json
import sys
import threading

import paho.mqtt.client as mqtt

from spea_lab_iot.key_agreement import KeyAgreement

# Topics (inline to avoid circular import; also in config.py)
TOPIC_DH_INIT     = "iot/dh/init"
TOPIC_DH_RESPONSE = "iot/dh/response"
TOPIC_DH_FINISH   = "iot/dh/finish"

HANDSHAKE_TIMEOUT_SEC = 15


def run_dh_handshake(
    client: mqtt.Client,
    device_id: str,
    pin: str,
    algorithm: str = "ecdh_ephemeral",
) -> bytes:
    """
    Perform the authenticated DH handshake.

    Returns the 32-byte session_key on success.
    Raises RuntimeError on timeout or authentication failure.
    """
    ka = KeyAgreement.create(algorithm, pin)
    our_pub = ka.public_key_bytes()

    response_event = threading.Event()
    result: dict = {}

    # ------------------------------------------------------------------ #
    # Step 3 — receive platform response                                   #
    # ------------------------------------------------------------------ #
    def _on_dh_message(
        client: mqtt.Client, userdata: object, msg: mqtt.MQTTMessage
    ) -> None:
        if msg.topic != TOPIC_DH_RESPONSE:
            return
        try:
            payload = json.loads(msg.payload.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        if payload.get("device_id") != device_id:
            return  # not for us

        peer_pub_hex = payload.get("public_key")
        hmac_received = payload.get("hmac_transcript")

        if not peer_pub_hex or not hmac_received:
            result["error"] = "Incomplete DH response from platform"
            response_event.set()
            return

        peer_pub = bytes.fromhex(peer_pub_hex)

        # ---------------------------------------------------------------- #
        # Step 4 — verify platform HMAC (MitM protection)                  #
        # transcript = device_id | our_pub | peer_pub                       #
        # ---------------------------------------------------------------- #
        transcript_parts = [device_id.encode(), our_pub, peer_pub]
        if not ka.verify_transcript_hmac(transcript_parts, hmac_received):
            result["error"] = "HMAC verification failed — possible MitM attack!"
            response_event.set()
            return

        # ---------------------------------------------------------------- #
        # Step 5 — derive session key                                       #
        # ---------------------------------------------------------------- #
        try:
            session_key = ka.derive_session_key(peer_pub)
        except ValueError as e:
            result["error"] = f"Key derivation error: {e}"
            response_event.set()
            return

        result["session_key"] = session_key
        result["peer_pub"] = peer_pub
        response_event.set()

    # Subscribe to DH response topic
    client.subscribe(TOPIC_DH_RESPONSE, qos=1)
    client.message_callback_add(TOPIC_DH_RESPONSE, _on_dh_message)

    # ------------------------------------------------------------------ #
    # Step 2 — send init message                                           #
    # ------------------------------------------------------------------ #
    init_payload = json.dumps({
        "device_id": device_id,
        "algorithm": algorithm,
        "public_key": our_pub.hex(),
    })
    client.publish(TOPIC_DH_INIT, init_payload, qos=1)
    print(f"[dh] Sent DH init (algorithm={algorithm})")

    # Wait for platform response
    if not response_event.wait(timeout=HANDSHAKE_TIMEOUT_SEC):
        client.message_callback_remove(TOPIC_DH_RESPONSE)
        raise RuntimeError("DH handshake timeout — no response from platform")

    client.message_callback_remove(TOPIC_DH_RESPONSE)

    if "error" in result:
        raise RuntimeError(f"DH handshake failed: {result['error']}")

    session_key: bytes = result["session_key"]
    peer_pub: bytes = result["peer_pub"]

    # ------------------------------------------------------------------ #
    # Step 6 — send finish (our HMAC to platform for mutual auth)          #
    # transcript = device_id | peer_pub | our_pub  (reversed order)        #
    # ------------------------------------------------------------------ #
    finish_transcript = [device_id.encode(), peer_pub, our_pub]
    finish_hmac = ka.make_transcript_hmac(finish_transcript)

    finish_payload = json.dumps({
        "device_id": device_id,
        "hmac_transcript": finish_hmac,
    })
    client.publish(TOPIC_DH_FINISH, finish_payload, qos=1)
    print(f"[dh] Handshake complete. session_key={session_key.hex()[:16]}...")

    # Return both keys for R5:
    #   session_key -> encryption key (AES-CBC or AES-GCM)
    #   auth_key    -> authentication key (HMAC for AES-CBC)
    auth_key = ka.auth_key_bytes()
    return session_key, auth_key