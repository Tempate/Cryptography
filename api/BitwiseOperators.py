from typing import List

def number_to_format(num: int, length: int, base: str) -> str:
    """ Convert a number to a base fixing it to the desired length. """
    bits = format(num, base)
    bits = '0' * (length - len(bits)) + bits

    return bits


def word_to_list(text: str, size: int = 8) -> List[int]:
    if type(text) == int:
        text = number_to_format(text, 512, base="b")

    """ Split a word (typically a sequence of bits) into a list of elements. """
    return [int(text[i:i + size], 2) for i in range(0, len(text), size)]


def list_to_word(list_: List[int], byte_size: int = 8) -> int:
    """ Represent a list of bytes (typically 8-bits long) as an int. """
    return int("".join([number_to_format(byte, byte_size, "b") for byte in list_]), 2)


def shift(word: int, offset: int, size: int = 8, d: str = "left") -> int:
    """ Shift rotation for a number of a given size. """
    b = number_to_format(word, size, "b")
    if d == "left":
        a = (b + "0" * offset)[-size:]
    else:
        a = b[:size-offset]

    return int(a, 2)


def rotate(word: int, offset: int, size: int = 8, d: str = "left") -> int:
    """ Perform bitwise rotation on a given byte of a specified size. """
    b = number_to_format(word, size, "b")
    b = b[offset:] + b[:offset] if d == "left" else b[:offset] + b[offset:]
    return int(b, 2)


def modular_sum(list_: List[int], max_bit_length: int) -> int:
    """ Add a list of elements module of n (sum(L) % n). """
    return sum(list_) & 2 ** max_bit_length - 1


def rol64(word: int, offset: int, size: int) -> int:
    """ Rotation used in SHA-3. Rotates a word so that i -> i+offset """
    if offset:
        return shift(word, offset, size, "left") ^ shift(word, size-offset, size, "right")
    else:
        return word
