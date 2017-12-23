import random
from typing import List

from core import aes, rsa


def encrypt(msg):
    """
    This is a hybrid implementation that encrypts messages with both
    symmetric and asymmetric cryptography.
    """
    key = generate_key()

    """ Encrypts the message using symmetric cryptography (i.e. AES) and a random key. """
    cipher = aes.encrypt(msg, key)

    """ Encrypts the key using asymmetric cryptography (i.e. RSA) so it can be securely sent. """
    ascii_key = "".join([chr(k) for k in key])
    encrypted_key = rsa.encrypt(ascii_key)

    print("Encrypted key: " + str(encrypted_key))

    return cipher


def generate_key() -> List[int]:
    """ Generate a cryptographically secure random key and convert it to an ASCII string. """
    return [random.SystemRandom().randint(0, 256) for _ in range(16)]
