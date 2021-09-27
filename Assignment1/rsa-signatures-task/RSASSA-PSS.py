from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from secret_data import rsa_key


def signRSAPSS(message: bytes) -> bytes:
    """Sign a message using our private key."""
    key = RSA.import_key(open('private_key.pem').read())
    hash = SHA256.new(message)
    signature = pss.new(key, salt_bytes=32).sign(hash)
    return signature


def verifyRSAPSS(message: bytes, signature: bytes) -> bool:
    """Verify a signature using our public key."""
    key = RSA.import_key(open('public_key.pem').read())
    hash = SHA256.new(message)
    verifier = pss.new(key)
    try:
        verifier.verify(hash, signature)
        print("The signature is authentic.")
        return True
    except (ValueError, TypeError):
        print("The signature is not authentic.")
        return False


def createKeypair():
    private_key = RSA.generate(3072)
    public_key = private_key.public_key()
    f = open('private_key.pem', 'wb')
    f.write(private_key.export_key('PEM'))
    f.close()
    f = open('public_key.pem', 'wb')
    f.write(public_key.export_key('PEM'))
    f.close()


def main():
    # createKeypair()
    message = b"Hello world"
    signature = signRSAPSS(message)
    verifyRSAPSS(message, signature)


if __name__ == "__main__":
    main()
