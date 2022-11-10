from server import Server
from tag import TagFactory
import pytest
from support import *
from pypuf.simulation import ArbiterPUF


def test_auth_100_tags():
    """Different tags should be able to authenticate in sequence."""
    factory = TagFactory()
    server = Server()
    tags = factory.manufacture_n_tags(100)

    for seed, tag in enumerate(tags):
        server.enroll_tag(tag, seed)

    for tag in tags:
        terminal = 0
        m1 = server.handle_message(MInit(), terminal)
        m2 = tag.handle_message(m1)
        m3 = server.handle_message(m2, terminal)
        m4 = tag.handle_message(m3)
        m5 = server.handle_message(m4, terminal)
        success = tag.handle_m5(m5)
        assert success


def test_auth_100_tags_parallel():
    """Many tags should be able to authenticate at the same time on different readers.
    In reality this would be limited by the number of deployed readers."""
    factory = TagFactory()
    server = Server()
    tags = factory.manufacture_n_tags(100)

    for seed, tag in enumerate(tags):
        server.enroll_tag(tag, seed)

    messages = {}
    for reader, tag in enumerate(tags):
        messages[reader] = {}
        m1 = server.handle_message(MInit(), reader)
        m2 = tag.handle_message(m1)
        messages[reader]['m2'] = m2

    for reader, tag in enumerate(tags):
        m2 = messages[reader]['m2']
        m3 = server.handle_message(m2, reader)
        m4 = tag.handle_message(m3)
        messages[reader]['m4'] = m4

    for reader, tag in enumerate(tags):
        m4 = messages[reader]['m4']
        m5 = server.handle_message(m4, reader)
        success = tag.handle_m5(m5)
        assert success


def test_auth_one_tag_100_times():
    """One tag should be able to authenticate an unlimited number of times in sequence."""
    factory = TagFactory()
    server = Server()
    tag = factory.manufacture_n_tags(1)[0]
    server.enroll_tag(tag, 0)

    for i in range(0, 100):
        m1 = server.handle_message(MInit(), 0)
        m2 = tag.handle_message(m1)
        m3 = server.handle_message(m2, 0)
        m4 = tag.handle_message(m3)
        m5 = server.handle_message(m4, 0)
        success = tag.handle_m5(m5)
        assert success


def test_switch_tag_during_authentication():
    """If the tag is switched during the authentication phase,
    authentication should be terminated"""
    factory = TagFactory()
    server = Server()
    tags = factory.manufacture_n_tags(2)

    for seed, tag in enumerate(tags):
        server.enroll_tag(tag, seed)

    tag1 = tags[0]
    tag2 = tags[1]

    m1 = server.handle_message(MInit(), 0)
    m2 = tag1.handle_message(m1)
    with pytest.raises(ValueError):
        m3 = server.handle_message(m2, 0)
        m4 = tag2.handle_message(m3)
        m5 = server.handle_message(m4, 0)
        success = tag.handle_m5(m5)


def test_tag_with_invalid_sid():
    """If the sid of the tag is changed after enrolling it, 
    a ValueError should be thrown on the server side when handling M2."""
    factory = TagFactory()
    server = Server()
    tag = factory.manufacture_n_tags(1)[0]
    server.enroll_tag(tag, 0)

    tag.sid = "changed_sid"

    m1 = server.handle_message(MInit(), 0)
    m2 = tag.handle_message(m1)
    with pytest.raises(ValueError):
        server.handle_message(m2, 0)


def test_tag_with_invalid_puf():
    """An enrolled tag with a PUF module, that was modified by an attacker,
    should not be able to authenticate."""
    factory = TagFactory()
    server = Server()
    tag = factory.manufacture_n_tags(1)[0]
    server.enroll_tag(tag, 0)

    attacker_puf = ArbiterPUF(n=CHALLENGE_LENGTH, seed=1)
    tag.puf = attacker_puf

    m1 = server.handle_message(MInit(), 0)
    m2 = tag.handle_message(m1)
    m3 = server.handle_message(m2, 0)
    with pytest.raises(ValueError):
        tag.handle_message(m3)
