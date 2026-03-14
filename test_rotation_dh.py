import sys
sys.path.insert(0, "src")

from spea_lab_iot.key_agreement import KeyAgreement

print("=== TEST ROTATION DH ===\n")

pin = "1234"
algorithm = "ecdh_ephemeral"

# Simuler une rotation : refaire un handshake DH
print("🔄 Simulation rotation #1")
ka1_device = KeyAgreement.create(algorithm, pin)
ka1_platform = KeyAgreement.create(algorithm, pin)

pub1_device = ka1_device.public_key_bytes()
pub1_platform = ka1_platform.public_key_bytes()

key1_device = ka1_device.derive_session_key(pub1_platform)
key1_platform = ka1_platform.derive_session_key(pub1_device)

print(f"   Session key: {key1_device.hex()[:16]}...")
assert key1_device == key1_platform
print("   ✅ Rotation 1 OK\n")

# Simuler rotation #2
print("🔄 Simulation rotation #2")
ka2_device = KeyAgreement.create(algorithm, pin)
ka2_platform = KeyAgreement.create(algorithm, pin)

pub2_device = ka2_device.public_key_bytes()
pub2_platform = ka2_platform.public_key_bytes()

key2_device = ka2_device.derive_session_key(pub2_platform)
key2_platform = ka2_platform.derive_session_key(pub2_device)

print(f"   Session key: {key2_device.hex()[:16]}...")
assert key2_device == key2_platform
print("   ✅ Rotation 2 OK\n")

# Vérifier que les clés sont différentes
assert key1_device != key2_device
print("✅ Les clés de rotation sont différentes (preuve que DH fonctionne)\n")

print("🎉 Test de rotation DH réussi !")