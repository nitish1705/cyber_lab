from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature

# Step 1: Generate keys
private_key = dsa.generate_private_key(key_size=1024)
public_key = private_key.public_key()

# Step 2: Sign the message
message = b"This is a secure message."
signature = private_key.sign(message, hashes.SHA256())

# Decode signature (optional, for display)
r, s = decode_dss_signature(signature)

print("Message:", message.decode())
print("Signature (r, s):")
print("r = ", r)
print("s = ", s)

# Step 3: Verify the signature
try:
    public_key.verify(signature, message, hashes.SHA256())
    print("\nSignature is valid. Verification successful.")
except Exception as e:
    print("\nSignature verification failed.")