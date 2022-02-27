from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization.ssh import serialize_ssh_private_key

# Generate a private Key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)


# Extract public key from private key
public_key = private_key.public_key()

# Convert private key into key bytes
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
print("Private key: \n", private_key_bytes)
# Convert public key into key bytes
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print("\nPublic key: \n", public_key_bytes)
# Convert the private key btýtes back to a key 
# There is no encryption so no password
private_key = serialization.load_pem_private_key(
    private_key_bytes,
    password=None,
    backend=default_backend()
)

# COnvert the publuc key bytes back to a key
public_key = serialization.load_pem_public_key(
    public_key_bytes,
    backend=default_backend()
)