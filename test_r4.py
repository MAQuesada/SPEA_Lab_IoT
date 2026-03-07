"""
Local test for R4 handshake without MQTT broker.
Simulates device and platform in the same process using queues.

Usage:
    python test_r4.py
"""

import queue
import threading
import sys

sys.path.insert(0, "src")

from spea_lab_iot.key_agreement import KeyAgreement

# ---------------------------------------------------------------------------
# MQTT simulation via queues
# ---------------------------------------------------------------------------

dh_init_q     = queue.Queue()
dh_response_q = queue.Queue()
dh_finish_q   = queue.Queue()

TIMEOUT = 5  # seconds

def separator(title):
    print(f"\n{'='*50}")
    print(f"  {title}")
    print('='*50)

# ---------------------------------------------------------------------------
# Test 1 — ECDH ephemeral (X25519), correct PIN
# ---------------------------------------------------------------------------
def test_ecdh_success():
    separator("TEST 1: ecdh_ephemeral — correct PIN")

    device_id = "sensor-test-01"
    pin       = "platform-pin"
    algorithm = "ecdh_ephemeral"

    result = {}

    # ---- DEVICE THREAD ----
    def device():
        ka  = KeyAgreement.create(algorithm, pin)
        pub = ka.public_key_bytes()

        # Send init
        dh_init_q.put({"device_id": device_id, "algorithm": algorithm, "public_key": pub.hex()})
        print(f"[device]   → dh/init  pub={pub.hex()[:16]}...")

        # Wait for response
        resp      = dh_response_q.get(timeout=TIMEOUT)
        peer_pub  = bytes.fromhex(resp["public_key"])
        hmac_recv = resp["hmac_transcript"]

        # Verify platform HMAC
        transcript = [device_id.encode(), pub, peer_pub]
        if not ka.verify_transcript_hmac(transcript, hmac_recv):
            result["error"] = "Platform HMAC invalid — MitM detected!"
            return

        print(f"[device]   ✓ Platform HMAC verified")

        # Derive session key
        session_key = ka.derive_session_key(peer_pub)
        result["device_sk"] = session_key

        # Send finish
        finish_transcript = [device_id.encode(), peer_pub, pub]
        finish_hmac = ka.make_transcript_hmac(finish_transcript)
        dh_finish_q.put({"device_id": device_id, "hmac_transcript": finish_hmac})
        print(f"[device]   → dh/finish hmac={finish_hmac[:16]}...")
        print(f"[device]   session_key={session_key.hex()[:16]}...")

    # ---- PLATFORM THREAD ----
    def platform():
        # Receive init
        init     = dh_init_q.get(timeout=TIMEOUT)
        did      = init["device_id"]
        algo     = init["algorithm"]
        peer_pub = bytes.fromhex(init["public_key"])
        print(f"[platform] ← dh/init  device={did!r} algo={algo}")

        # Generate key pair and derive session key
        ka  = KeyAgreement.create(algo, pin)
        pub = ka.public_key_bytes()
        session_key = ka.derive_session_key(peer_pub)

        # Send response with HMAC
        transcript = [did.encode(), peer_pub, pub]
        hmac_hex   = ka.make_transcript_hmac(transcript)
        dh_response_q.put({"device_id": did, "public_key": pub.hex(), "hmac_transcript": hmac_hex})
        print(f"[platform] → dh/response pub={pub.hex()[:16]}...")

        # Receive finish
        finish = dh_finish_q.get(timeout=TIMEOUT)
        finish_transcript = [did.encode(), pub, peer_pub]
        if not ka.verify_transcript_hmac(finish_transcript, finish["hmac_transcript"]):
            result["error"] = "Device finish HMAC invalid!"
            return

        result["platform_sk"] = session_key
        print(f"[platform] ✓ Device HMAC verified")
        print(f"[platform] session_key={session_key.hex()[:16]}...")

    t_platform = threading.Thread(target=platform)
    t_device   = threading.Thread(target=device)
    t_platform.start()
    t_device.start()
    t_platform.join(timeout=TIMEOUT+1)
    t_device.join(timeout=TIMEOUT+1)

    if "error" in result:
        print(f"\n❌ FAILED: {result['error']}")
        return False

    if result.get("device_sk") == result.get("platform_sk"):
        print(f"\n✅ SUCCESS — session keys match on both sides")
        return True
    else:
        print(f"\n❌ FAILED — session keys do not match!")
        return False


# ---------------------------------------------------------------------------
# Test 2 — auth_dh (classic DH 2048-bit), correct PIN
# ---------------------------------------------------------------------------
def test_dh_success():
    separator("TEST 2: auth_dh — correct PIN")

    device_id = "sensor-test-02"
    pin       = "platform-pin"
    algorithm = "auth_dh"

    ka_d = KeyAgreement.create(algorithm, pin)
    ka_p = KeyAgreement.create(algorithm, pin)

    pub_d = ka_d.public_key_bytes()
    pub_p = ka_p.public_key_bytes()

    print(f"[device]   pub={pub_d.hex()[:16]}...")
    print(f"[platform] pub={pub_p.hex()[:16]}...")

    sk_d = ka_d.derive_session_key(pub_p)
    sk_p = ka_p.derive_session_key(pub_d)

    transcript = [device_id.encode(), pub_d, pub_p]
    hmac_p = ka_p.make_transcript_hmac(transcript)
    valid  = ka_d.verify_transcript_hmac(transcript, hmac_p)

    if sk_d == sk_p and valid:
        print(f"[both]     session_key={sk_d.hex()[:16]}...")
        print(f"\n✅ SUCCESS — classic DH OK")
        return True
    else:
        print(f"\n❌ FAILED")
        return False


# ---------------------------------------------------------------------------
# Test 3 — simulated MitM (wrong PIN on platform side)
# ---------------------------------------------------------------------------
def test_mitm_detection():
    separator("TEST 3: simulated MitM — platform with wrong PIN")

    device_id = "sensor-test-03"
    real_pin  = "platform-pin"
    mitm_pin  = "hacked-pin"
    algorithm = "ecdh_ephemeral"

    ka_device = KeyAgreement.create(algorithm, real_pin)
    ka_mitm   = KeyAgreement.create(algorithm, mitm_pin)  # attacker

    pub_d    = ka_device.public_key_bytes()
    pub_mitm = ka_mitm.public_key_bytes()

    # MitM sends HMAC signed with wrong PIN
    transcript = [device_id.encode(), pub_d, pub_mitm]
    hmac_mitm  = ka_mitm.make_transcript_hmac(transcript)

    # Device verifies with real PIN — must fail
    valid = ka_device.verify_transcript_hmac(transcript, hmac_mitm)

    if not valid:
        print(f"[device]   ✓ HMAC rejected — MitM attack detected!")
        print(f"\n✅ SUCCESS — MitM correctly blocked")
        return True
    else:
        print(f"\n❌ FAILED — MitM not detected!")
        return False


# ---------------------------------------------------------------------------
# Test 4 — invalid algorithm
# ---------------------------------------------------------------------------
def test_invalid_algorithm():
    separator("TEST 4: invalid algorithm")
    try:
        KeyAgreement.create("rsa_oops", "pin")
        print("❌ FAILED — should have raised ValueError")
        return False
    except ValueError as e:
        print(f"✓ ValueError raised: {e}")
        print(f"\n✅ SUCCESS")
        return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    results = [
        test_ecdh_success(),
        test_dh_success(),
        test_mitm_detection(),
        test_invalid_algorithm(),
    ]

    separator("SUMMARY")
    passed = sum(results)
    total  = len(results)
    print(f"{passed}/{total} tests passed")
    if passed == total:
        print("🎉 All R4 tests pass!")
    else:
        print("⚠️  Some tests failed.")
        sys.exit(1)