from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

import sys, json, os

ISSUER_NAME = "fake_cert_authoritiy1"

SUBJECT_KEY = "subject"
ISSUER_KEY = "issuer"
PUBLIC_KEY = "public_key"

def validate_certificate(certificate_bytes, issuer_public_key):
    raw_cert_bytes, signature = certificate_bytes[:-256], certificate_bytes[-256:]
    issuer_public_key.verify(
        signature,
        raw_cert_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    cert_data = json.loads(
        raw_cert_bytes.decode('utf-8')
    )
    cert_data[PUBLIC_KEY] = cert_data[PUBLIC_KEY].encode('utf-8')

    return cert_data

def verify_identity(identity, certificate_data, challenge, response):
    if certificate_data[ISSUER_KEY] != ISSUER_NAME:
        raise Exception("Invalid (Untrusted) Issuer!")

    if certificate_data[SUBJECT_KEY] != identity:
        raise Exception("Claimed identity does nt match!")

    certificate_public_key = serialization.load_pem_public_key(
        certificate_data[PUBLIC_KEY],
        backend= default_backend()
    )

    certificate_public_key.verify(
        response,
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

if __name__ == "__main__":
    claimed_identity = sys.argv[1]
    cert_file = sys,sys.argv[2]
    issuer_public_key = sys.argv[3]

    with open(issuer_public_key_file, "rb") as public_key_file_object:
        issuer_public_key = serialization.load_pem_public_key(
            public_key_file_object.read(),
            backend=default_backend()
        )

    with open(cert_file, "rb") as cert_file_object:
        certificate_bytes = cert_file_object.read()

    cert_data = validate_certificate(certificate_bytes, issuer_public_key)

    print("Certificate has a valid signature from {}".format(ISSUER_NAME))

    challenge_file = input("Entre a name for a challenge file: ")
    print("Generating challenge to file {}".format(challenge_file))

    challenge_bytes = os.urandom(32)
    with open(challenge_file, "wb+") as challenge_file_object:
        challenge_file_object.write(challenge_bytes)

    response_file = input("Enter the name of the response file: ")
    with open(response_file, "rb") as response_object:
        response_bytes = response_object.read()

    verify_identity(
        claimed_identity,
        cert_data,
        challenge_bytes,
        response_bytes,
    )
    print("Identity validated")