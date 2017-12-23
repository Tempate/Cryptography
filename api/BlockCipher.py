from api.BitwiseOperators import *


def bytes_to_words(bytes_: List[int], block_size: int) -> List[int]:
    """ Converts a list of bytes to a list of words (size: block_size) """
    blocks = []

    for i in range(0, len(bytes_), block_size):
        blocks.append(bytes_[i:i+block_size])

    return blocks

def msg_to_bytes(msg: str) -> List[int]:
    return [ord(char) for char in msg]


def ansi_x932(bytes_: List[int], block_size: int) -> List[int]:
    """
    ANSI X.923
    (N - 1) zero bytes are added, plus a byte with the value of N.
    """
    bytes_to_add = block_size - len(bytes_) % block_size

    if bytes_to_add > 0:
        bytes_.extend([0] * (bytes_to_add - 1))
        bytes_.append(bytes_to_add)

    return bytes_to_words(bytes_, block_size)


def pkcs7(bytes_: List[int], block_size: int) -> List[int]:
    """
    PKCS#7 is described in RFC 5652.
    The value of each added byte is the number of bytes that are added.
    N bytes are added with the value of N.
    """
    bytes_to_add = block_size - len(bytes_) % block_size
    bytes_.extend([bytes_to_add] * bytes_to_add)

    return bytes_to_words(bytes_, block_size)
