from src.cryptopals.utils import *
from pytest import raises


def test_hex_to_base64():
    # bytearray
    assert hex_to_base64(
        bytearray.fromhex(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        )
    ) == bytearray(b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

    # bytes
    with raises(ValueError):
        hex_to_base64(b"68656c6c6f2c20776f726c6421")

    # others
    with raises(ValueError):
        hex_to_base64(1)

    with raises(ValueError):
        hex_to_base64(1.1)

    with raises(ValueError):
        hex_to_base64("1231231231231231")


def test_fixed_xor():
    assert fixed_xor(
        bytearray.fromhex("1c0111001f010100061a024b53535009181c"),
        bytearray.fromhex("686974207468652062756c6c277320657965"),
    ) == bytearray(b"the kid don't play")
