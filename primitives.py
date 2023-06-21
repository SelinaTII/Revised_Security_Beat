import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Secret value for test only
# Will be derived from ECDH keys in code
secret_1_2 = b'\xf1\x05\xe4!\x89\tZu\x8d\xe6U\xa8\x8e{y\xa8d\xe5\x89&\x14\x967\xbbUA\x12\xb3*\xc43' # ECDH shared secret between node 1 and 2
secret_1_3 = b'\xe8U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x8c\x91\x8e)%\xacN\xd9\xd8\x8d\xe8x14\xb5' # ECDH shared secret between node 1 and 3
secret_1_4 = b'\xe7U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x8c\x91\x8e)%\xacN\xd9\xd8\x8d\xe8x14\xb4' # ECDH shared secret between node 1 and 4
secret_1_5 = b'\xe7U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x8c\x91\x8e)%\xacN\xd9\xd8\x8d\xe8x14\xb3' # ECDH shared secret between node 1 and 5
secret_1_6 = b'\xe7U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x8c\x81\x8e)%\xacN\xd9\xd8\x8d\xe8x14\xb3' # ECDH shared secret between node 1 and 6
secret_2_3 = b'\xe6U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x8c\x91\x8e)%\xacN\xd9\xd8\x8d\xe8x14\xb3' # ECDH shared secret between node 2 and 3
secret_2_4 = b'\xe5U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x8c\x91\x8e)%\xacN\xd9\xd8\x8d\xe8x14\xb2' # ECDH shared secret between node 2 and 4
secret_3_4 = b'\xe4U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x8c\x91\x8e)%\xacN\xd9\xd8\x8d\xe8x14\xb1' # ECDH shared secret between node 3 and 4
secret_2_5 = b'\xe7U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x7c\x91\x8e)%\xacN\xd9\xd8\x8d\xe8x14\xb3' # ECDH shared secret between node 2 and 5
secret_3_5 = b'\xe7U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x6c\x91\x8e)%\xacN\xd9\xd8\x8d\xe8x14\xb3' # ECDH shared secret between node 3 and 5
secret_4_5 = b'\xe7U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x5c\x91\x8e)%\xacN\xd9\xd8\x8d\xe8x14\xb3' # ECDH shared secret between node 4 and 5
secret_2_6 = b'\xe7U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x8c\x71\x8e)%\xacN\xd9\xd8\x8d\xe8x14\xb3' # ECDH shared secret between node 2 and 6
secret_4_7 = b'\xe7U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x8c\x61\x8e)%\xacN\xd9\xd8\x8d\xe8x14\xb3' # ECDH shared secret between node 4 and 7
def encrypt_response(data, secret):
    # 256 bit key derivation from secret and random salt
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=48000,
    )
    key = kdf.derive(secret)

    # AESGCM encryption using derived key and random nonce
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    cipthertext = aesgcm.encrypt(nonce, data, associated_data=None)
    message = salt + nonce + cipthertext  # Message to send: First 16 bytes: salt, Next 12 bytes: nonce, Next: ciphertext
    return message

def decrypt_response(message, secret):
    # First 16 bytes: salt, Next 12 bytes: nonce, Next: ciphertext
    salt = message[:16]
    nonce = message[16:16 + 12]
    ciphertext = message[16 + 12:]

    # 256 bit key derivation from secret and received salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=48000,
    )
    key = kdf.derive(secret)

    # AESGCM encryption using derived key and received nonce
    aesgcm = AESGCM(key)
    data = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return data



