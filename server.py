import tag
from pypuf.io import random_inputs
from uuid import uuid4
from bitstring import BitArray
from support import *


class Server:
    # Singleton pattern allows only one server to exist
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Server, cls).__new__(cls)
        return cls.instance

    def __init__(self) -> None:
        self.persistent_storage = {}
        self.active_sessions = {}
        pass

    class AuthSession():
        def __init__(self) -> None:
            self.sid: str = None
            self.next_sid: str = None
            self.challenge: BitArray = None
            self.next_challenge: BitArray = None
            self.response: BitArray = None
            self.next_resp: BitArray = None
            self.n: BitArray = None
            self.n_mod: BitArray = None
            self.resp_mod: BitArray = None
            self.m: BitArray = None
            self.m_mod: BitArray = None
            self.m_plus_1: BitArray = None
            self.m_plus_2: BitArray = None
            self.auth1: HASH_FUNCTION = None
            self.auth2_tag: HASH_FUNCTION = None
            self.auth2: HASH_FUNCTION = None
            self.auth3: HASH_FUNCTION = None
            pass

    def enroll_tag(self, tag: tag.Tag, challenge_seed: int) -> None:
        challenge = self.generate_random_challenge(challenge_seed)
        response = self.challenge_tag(tag, challenge)
        sid = self.generate_initial_random_session_identity()
        self.store_identity(sid, challenge, response)
        tag.set_sid(sid)
        print("Enrolled Tag with SID ", sid)

    def generate_random_challenge(self, seed: int) -> BitArray:
        return array_to_bitstring(random_inputs(
            n=CHALLENGE_LENGTH,
            N=RESPONSE_LENGTH,
            seed=seed))

    def challenge_tag(self, tag: tag.Tag, challenge: BitArray) -> BitArray:
        return tag.generate_response(challenge)

    def generate_initial_random_session_identity(self) -> str:
        h = new_hash(bytes(str(uuid4()), 'utf-8'))
        return h.hexdigest()

    def store_identity(self, sid: str, challenge: BitArray, resp: BitArray) -> None:
        self.persistent_storage[sid] = {
            "c": challenge,
            "r": resp
        }

    def remove_identity(self, sid: str) -> None:
        del self.persistent_storage[sid]

    def handle_m2(self, m, session: AuthSession) -> M3:
        session.sid = m.sid
        try:
            session.challenge = self.persistent_storage[session.sid]["c"]
            session.response = self.persistent_storage[session.sid]["r"]
        except KeyError:
            raise ValueError(
                "Invalid SID sent by tag.\nTag might be invalid. Authentication terminated.")

        session.n = generate_random_bitstring(RESPONSE_LENGTH)
        session.n_mod = xor(session.response, session.n)
        session.auth1 = new_hash(
            bytes(concat(session.n, session.response).hex, 'utf-8'))
        return M3(session.challenge, session.n_mod, session.auth1)

    def handle_m4(self, message: M4, session: AuthSession) -> M5:
        session.resp_mod = message.resp_mod
        session.m_mod = message.m_mod
        auth2_tag = message.auth2

        session.next_resp = xor(session.resp_mod, session.n)
        session.m = xor(session.m_mod, session.n)
        session.m_plus_1 = add_int_to_bitstring(session.m, 1)

        session.auth2 = new_hash(bytes(concat(
            concat(session.n, session.m_plus_1), session.next_resp).hex, 'utf-8'))
        verify_hash(auth2_tag, session.auth2)

        session.next_challenge = compute_next_challenge(
            session.n, session.m, session.challenge)
        session.m_plus_2 = add_int_to_bitstring(session.m, 2)
        session.next_sid = new_hash(bytes(concat(concat(
            session.n, session.m_plus_2), BitArray(hex=session.sid)).hex, 'utf-8')).hexdigest()
        session.auth3 = new_hash(
            bytes(concat(session.n, session.m_plus_2).hex, 'utf-8'))

        self.store_identity(
            session.next_sid, session.next_challenge, session.next_resp)

        print("Authentication of tag successful on server side!")
        print("Identity for next auth session: ", session.next_sid)

        return M5(session.auth3)

    def handle_message(self, m: AuthMessage, reader_id: int) -> None:
        if reader_id in self.active_sessions:
            session = self.active_sessions[reader_id]
        else:
            session = self.AuthSession()
            self.active_sessions[reader_id] = session
            session.expected_message = MInit
        if type(m) != session.expected_message:
            raise TypeError(
                f"Expected {session.expected_message}, got {type(m)}")
        elif (type(m)) == MInit:
            session.expected_message = M2
            return M1()
        elif (type(m)) == M2:
            session.expected_message = M4
            return self.handle_m2(m, session)
        elif (type(m)) == M4:
            m = self.handle_m4(m, session)
            del self.active_sessions[reader_id]

            print(f"Tag at reader {reader_id} successfully authenticated.")
            print("New session identity written to persistent storage\n")
            return m
        else:
            raise TypeError("Unknown Message Type")
