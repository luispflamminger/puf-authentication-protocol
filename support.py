import hashlib
import random
import numpy as np
from bitstring import BitArray

CHALLENGE_LENGTH = 64
RESPONSE_LENGTH = 16  # number of evaluations of arbiter puf per response
HASH_FUNCTION = hashlib.sha256


def array_to_bitstring(np_array: np.ndarray) -> BitArray:
    """
    Flattens a nested array consisting of a challenge or response for an Arbiter PUF
    Arbiter PUF output -1 is interpreted as binary 0, output 1 is interpreted as binary 1)
    """

    np_array = np_array.flatten()
    np_array[np_array == -1] = 0
    return BitArray(np_array)


def bitstring_to_challenge(b: BitArray, n: int = CHALLENGE_LENGTH, N: int = RESPONSE_LENGTH) -> np.ndarray:
    """Converts a BitArray to a numpy array of shape (N, n)"""
    flat = []
    shaped = [None]*N
    for c in b.bin:
        flat.append(c)
    for i in range(0, N):
        shaped[i] = flat[n*(i):n*(i+1)]
    shaped = np.array(shaped, dtype='int8')
    shaped[shaped == 0] = -1
    return shaped


def xor(n: BitArray, m: BitArray) -> BitArray:
    """Takes two BitArrays of length n and applies XOR logic to each bit"""
    if len(n) != len(m):
        raise ValueError("XOR inputs of different lengths are not supported!")
    return BitArray(bin=bin(int(n.bin, 2) ^ int(m.bin, 2))[2:].zfill(len(n)))


def concat(n: BitArray, m: BitArray) -> BitArray:
    """Concatinates two BitArrays"""
    return n + m


def new_hash(v) -> HASH_FUNCTION:
    """Returns a new hash of value v"""
    h = HASH_FUNCTION()
    h.update(v)
    return h


def verify_hash(h1, h2):
    """Checks if hashes h1 and h2 are matching"""
    try:
        assert h1.hexdigest() == h2.hexdigest()
    except:
        raise ValueError(
            f"Hash could not be verified!\nHash 1: {h1.hexdigest()}\nHash 2: {h2.hexdigest()}")


def generate_random_bitstring(l: int) -> BitArray:
    """Generates a random BitArray of length l"""
    n = [0]  # first bit is always zero to prevent overflows on addition
    for i in range(0, l-1):
        n.append(random.randint(0, 1))
    n = BitArray(n)
    return n


def add_int_to_bitstring(b: BitArray, i: int):
    """
    Increases binary value of BitArray by bin(i)
    If resulting BitArray is too large to fit in len(b), an error is thrown
    """
    return BitArray(int=b.int+i, length=len(b))


def compute_next_challenge(n, m, c):
    """
    Computes the next challenge based on a concatination of two random numbers and the previous challenge.
    This is done by hashing the resulting bitstring and multiplying it until the required challenge length is reached.
    """
    h = new_hash(bytes(concat(concat(n, m), c).hex, 'utf-8'))
    h = BitArray(h.digest())
    s = CHALLENGE_LENGTH * RESPONSE_LENGTH
    while len(h) < s:
        h = h + h
    return h[0:s]


class AuthMessage:
    """Base class for authentication messages"""
    pass


class MInit(AuthMessage):
    pass


class M1(AuthMessage):
    pass


class M2(AuthMessage):
    def __init__(self, sid) -> None:
        super().__init__()
        self.sid = sid


class M3(AuthMessage):
    def __init__(self, challenge, n_mod, auth1) -> None:
        super().__init__()
        self.challenge = challenge
        self.n_mod = n_mod
        self.auth1 = auth1


class M4(AuthMessage):
    def __init__(self, resp_mod, m_mod, auth2) -> None:
        super().__init__()
        self.resp_mod = resp_mod
        self.m_mod = m_mod
        self.auth2 = auth2


class M5(AuthMessage):
    def __init__(self, auth3) -> None:
        super().__init__()
        self.auth3 = auth3
