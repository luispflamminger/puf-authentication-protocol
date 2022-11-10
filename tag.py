from bitstring import BitArray
from pypuf.simulation import ArbiterPUF
from support import *
from typing import List


class TagFactory:
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(TagFactory, cls).__new__(cls)
        return cls.instance

    def __init__(self) -> None:
        pass

    # ensure uniqueness of PUFs
    total_produced_tags = 0

    def manufacture_n_tags(self, n) -> List['Tag']:
        tags = []
        for i in range(0, n):
            seed = self.total_produced_tags
            puf = ArbiterPUF(n=CHALLENGE_LENGTH, seed=seed)
            tags.append(Tag(puf))
            print(f"Tag with seed {seed} manufactured")
            self.total_produced_tags += 1

        return tags


class Tag:
    def __init__(self, puf_module: ArbiterPUF) -> None:
        self.puf = puf_module
        self.sid = None
        self.enrolled = False

    def generate_response(self, challenge: BitArray) -> BitArray:
        challenge = bitstring_to_challenge(challenge)
        return array_to_bitstring(self.puf.eval(challenge))

    def set_sid(self, sid: str) -> None:
        self.sid = sid

    def handle_message(self, m: AuthMessage) -> None:
        if (type(m)) == M1:
            return self.handle_m1()
        elif (type(m)) == M3:
            return self.handle_m3(m)
        elif (type(m)) == M5:
            return self.handle_m3(m)
        else:
            raise TypeError

    def handle_m1(self) -> M2:
        return M2(self.sid)

    def handle_m3(self, message: M3) -> M4:
        challenge = message.challenge
        n_mod = message.n_mod
        auth1 = message.auth1
        resp = self.generate_response(challenge)
        n = xor(n_mod, resp)
        self.n = n
        verify_hash(auth1, new_hash(
            bytes(concat(n, resp).hex, 'utf-8')))
        m = generate_random_bitstring(RESPONSE_LENGTH)
        next_challenge = compute_next_challenge(n, m, challenge)
        next_response = self.generate_response(next_challenge)
        resp_mod = xor(next_response, n)
        m_mod = xor(m, n)
        m_plus_1 = add_int_to_bitstring(m, 1)
        self.m_plus_1 = m_plus_1
        auth2 = new_hash(bytes(concat(
            concat(n, m_plus_1), next_response).hex, 'utf-8'))
        return M4(resp_mod, m_mod, auth2)

    def handle_m5(self, m: M5) -> bool:
        m_plus_2 = add_int_to_bitstring(self.m_plus_1, 1)
        auth3_server = m.auth3
        auth3_comp = new_hash(
            bytes(concat(self.n, m_plus_2).hex, 'utf-8'))
        verify_hash(auth3_server, auth3_comp)
        next_sid = new_hash(bytes(concat(concat(
            self.n, m_plus_2), BitArray(hex=self.sid)).hex, 'utf-8')).hexdigest()
        self.sid = next_sid

        print("Authentication on tag side successful:")
        print("New session identity provisioned: ", self.sid)

        return True
