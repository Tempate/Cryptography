import numpy as np

from api.BitwiseOperators import *

K = np.array([
    0x5A827999,
    0x6ED9EBA1,
    0x8F1BBCDC,
    0xCA62C1D6]
    , dtype=object)


def hash_sum(msg):
    """
    Converts a message to a list of 512-bit blocks, each of them a list of 32-bit words.
    Recursively executes a compression function for every block.
    :return: Hash of the given message.
    """
    sha1 = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    blocks = padding(msg)

    for block in blocks:
        sha1 = compression(block, sha1)

    sha1 = "".join(number_to_format(word, 8, base="x") for word in sha1)

    return sha1


def padding(msg: str) -> List[str]:
    """
    Converts the message to bits. Appends '1' + '0' * x + bits64(msg.length)
    :return: List of blocks (512 bits).
    """
    msg = "".join(number_to_format(ord(char), length=8, base="b") for char in msg)
    msg_length = number_to_format(len(msg), length=64, base="b")

    zero_length = 448 - (len(msg) % 512)
    padd = "1"

    if zero_length > 0:
        padd += "0" * (zero_length - 1)

    padded_message = msg + padd + msg_length

    return word_to_list(padded_message, 512)


def compression(block: str, sha1_: str) -> str:
    sha1 = sha1_
    words = word_to_list(block, 32)  # Split message into 32-bit words.
    w = message_schedule(words)  # Expand the list of words (16->80).

    # Execute the round function recursively. Adding a word, a stage function and a constant.
    for j in range(80):
        sha1 = round_func(sha1, word=w[j], stage=(j // 20))

    for i in range(5):
        sha1[i] = modular_sum([sha1[i], sha1_[i]], 32)

    return sha1


def message_schedule(w: List[int]) -> List[int]:
    """ Expands the 16 input words to 80. """
    for j in range(16, 80, 1):
        w.append(rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], offset=1, size=32, d="left"))

    return w


def round_func(data: List[int], word: int, stage: int):
    """ Main encryption function. """
    new_data = [0] * 5

    new_data[1] = data[0]
    new_data[2] = rotate(data[1], 30, 32, "left")
    new_data[3] = data[2]
    new_data[4] = data[3]

    func = stage_function(data[1], data[2], data[3], stage=stage)
    new_data[0] = modular_sum([
        data[4],                            # E
        func,                               # Specific stage function
        rotate(data[0], 5, 32, "left"),     # A <<< 5
        word,                               # Word
        K[stage]                            # Constant
    ], 32)

    return new_data


def stage_function(b: int, c: int, d: int, stage: int) -> int:
    """ Performs a different function for each of the four stages. """
    if stage == 0:
        return (b & c) | (~b & d)
    elif stage == 2:
        return (b & c) | (b & d) | (c & d)
    else:
        return b ^ c ^ d
