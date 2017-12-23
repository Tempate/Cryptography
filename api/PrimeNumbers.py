import math
import random


def get_primes(n: int, bits: int):
    """ Creates a tuple of n different primes of an approximate binary length (bits).  """
    primes = set()

    while len(primes) != n:
        p = random_prime(bits)
        primes.add(p)

    primes = sorted(primes)

    return tuple(primes)


def random_prime(bits: int) -> int:
    min_ = int(math.sqrt(2) * pow(2, bits - 1))
    max_ = pow(2, bits) - 1

    while True:
        """
        This is a cryptographically secure pseudo-random number generator.
        It uses os.urandom().
        """
        p = random.SystemRandom().randint(min_, max_)

        if miller_rabin_primality_test(p):
            return p


def fermats_primality_test(n: int, k: int = 100) -> bool:
    """
    Fermat's little theorem states that if p is prime and a is not divisible by p:
        a^(p - 1) = 1 (mod p)
    To check if a number n is prime, we can pick random a's and check if the equation holds.
    This is the simplest way of probabilistically checking if a number is prime.
    :param n: number to check.
    :param k: number of times to check.
    """
    for i in range(k):
        # WARNING: This is not a cryptographically secure RNG.
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False

    return True


def miller_rabin_primality_test(n: int, k: int = 100) -> bool:
    """
    Miller-Rabin's test is an improvement upon Fermat's test.
    :param n: number to check.
    :param k: number of times to check.
    """
    if n < 3 or n % 2 == 0:
        return False

    # n - 1 = 2^r * d
    r, d = 0, n - 1

    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        composite = True

        for i in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
            elif x == 1:
                return False

        if composite:
            return False

    return True
