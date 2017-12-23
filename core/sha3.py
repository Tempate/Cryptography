import numpy as np

from api.BitwiseOperators import *

n = 24
r = 1088
w = 64

"""
RC[i] = sum([rc(j + 7i) for j in range(6)])
rc(t) = (x^t mod x^8 + x^6 + x^5 + x^4 + 1) mod x in GF(2)[x]
"""
Round_Constants = np.array([
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
], dtype=object)

"""
d(V)= sum([-1^i r[point i] for i in range(2e-1)])
"""
Rotation_Offsets = np.array([
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14]
], dtype=object)


def hash_sum():
    msg = "a"  # sys.argv[1]

    p = pre_processing(msg)
    z = inner_keccak(p)

    print("SHA-3: %s" % z)


def pre_processing(msg: str) -> List[str]:
    """
    Functionality -- Splits the message into blocks of r bits.
    Padding -- Appends ('1' + '0'x + '1') to the message.
    """
    msg = "".join(number_to_format(ord(char), 8, "b") for char in msg)

    junk_length = r - (len(msg) + 1) % r - 1
    msg += "1" + "0" * junk_length + "1"

    return word_to_list(msg, r)


def inner_keccak(data: List[str]) -> str:
    """ Converts an input of random length to a fixed length number (256-bits). """
    s = absorb(data)
    z = squeeze(s)

    return z


def absorb(data: List[str]):
    """
    Shuffles and compresses the message.
    :return: two-dimensional array of words (64-bits).
    """
    s = np.zeros((5, 5), dtype=object)

    for block in data:
        word = word_to_list(block, 64)

        for x in range(r // w):
            y = 0

            while x + 5 * y < r // w:
                s[x % 5, y % 5] ^= int(word[x + 5 * y], 2)
                s = keccak_func(s)
                y += 1

    return s


def keccak_func(state):
    """
    It takes the state (5x5 64-bits), scrambles, shuffles and adds a set of constants.
    This process makes it very hard to reverse.
    :return: two-dimensional array of words (64-bits).
    """
    for i in range(n):
        state = theta(state)
        state = rho(state)
        state = pi(state)
        state = chi(state)
        state = iota(state, Round_Constants[i])

    return state


def theta(state):
    """ Computes the parity of each of the 5x5 columns. """
    a = np.zeros((5,), dtype=object)
    b = np.zeros((5,), dtype=object)

    for x in range(5):
        for y in range(5):
            a[x] ^= state[x, y]

    for x in range(5):
        b[x] = a[(x + 4) % 5] ^ rol64(a[(x + 1) % 5], 1)

    for x in range(5):
        for y in range(5):
            state[x, y] ^= b[x]

    return state


def rho(state):
    """ Bitwise rotate each of the 25 words by a different triangular number. """
    new_state = np.zeros((5, 5), dtype=object)

    for x in range(5):
        for y in range(5):
            new_state[x, y] = rol64(state[x, y], Rotation_Offsets[x, y])

    return new_state


def pi(state):
    """ Permutes the 5x5 words in a fixed pattern. """
    new_state = np.zeros((5, 5), dtype=object)

    for x in range(5):
        for y in range(5):
            new_state[y, (2 * x + 3 * y) % 5] = state[x, y]

    return new_state


def chi(state):
    """
    This is the only non-linear operation in SHA-3
    Bitwise combine along rows, mixing the state.
    x ← x ⊕ (¬y & z)
    """
    new_state = np.zeros((5, 5), dtype=object)

    for y in range(5):
        for x in range(5):
            new_state[x, y] = state[x, y] ^ (~state[(x + 1) % 5, y] & state[(x + 2) % 5, y])

    return new_state


def iota(state, round_constant):
    """ Exclusive-or a round constant into one word of the state. """
    state[0, 0] ^= round_constant
    return state


def squeeze(s):
    """ Squeezes the state out of the sponge. """
    z = ""

    while len(z) < 64:
        for x in range(r // w):
            y = 0

            while x + 5 * y < r / w:
                z += number_to_format(s[x % 5, y % 5], 16, "x")
                y += 1

    return z[:64]


if __name__ == "__main__":
    main()
