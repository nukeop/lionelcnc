import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PRIVATE_KEY_FILENAME = "key.pem"

logger = logging.getLogger(__name__)

class Crypto(object):
    """Creates a public/private key pair or loads it from a file if it exists.
    """
    def __init__(self, keyfile=PRIVATE_KEY_FILENAME):
        if os.path.exists(keyfile):
            logger.info("Loading a private key from {}".format(keyfile))
            with open(keyfile, 'rb') as keyfile:

                self.private_key = serialization.load_pem_private_key(
                    keyfile.read(),
                    password=None,
                    backend=default_backend()
                )
                self.public_key = self.private_key.public_key()
        else:
            logger.info("Creating a new private key and storing it in"
                        "{}".format(keyfile)) 
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(keyfile, 'wb') as keyfile:
                keyfile.write(pem)

            self.public_key = self.private_key.public_key()


