from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# 1. Generate Keys
alice_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
bob_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

message = b"Payment of $5000 authorized."

# 2. Alice Signs the message (Simple PKCS1v15 padding)
signature = alice_private.sign(message, padding.PKCS1v15(), hashes.SHA256())

# 3. Encrypt the message for Bob (Simple PKCS1v15 padding)
ciphertext = bob_private.public_key().encrypt(message, padding.PKCS1v15())

# 4. Bob Decrypts the message
decrypted_message = bob_private.decrypt(ciphertext, padding.PKCS1v15())

# 5. Bob Verifies Alice's signature
alice_private.public_key().verify(signature, decrypted_message, padding.PKCS1v15(), hashes.SHA256())

print(f"Decrypted Message: {decrypted_message.decode()}")
print("Signature verified successfully!")