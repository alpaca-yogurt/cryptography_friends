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


def test_get_bytearray_of_all_characters():
    assert (
        get_bytearray_of_all_characters()
        == b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
    )


def test_single_byte_xor():
    assert (
        single_byte_xor(
            ord("X"), bytearray.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        )
    ) == b"Cooking MC's like a pound of bacon"


def test_score_english_text():
    # see comment in function
    assert (score_english_text("Cooking MC's like a pound of bacon")) == 251


def test_repeating_key_xor():
    assert (
        (
            repeating_key_xor(
                bytearray(b"ICE"),
                bytearray("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".encode()),
            ).hex()
        )
        == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    )


def test_hamming_distance():
    assert (hamming_distance(bytearray(b"this is a test"), bytearray(b"wokka wokka!!!"))) == 37


def test_pkcs_pad_buffer():
    assert pkcs_pad_buffer(bytearray("YELLOW SUBMARINE".encode()), 20) == bytearray(
        "YELLOW SUBMARINE\x04\x04\x04\x04".encode()
    )
    # pad bytes that are a multiple of the block size
    assert pkcs_pad_buffer(bytearray.fromhex("971ACD01C9C7ADEACC83257926F490FF"), 16) == bytearray.fromhex(
        "971ACD01C9C7ADEACC83257926F490FF10101010101010101010101010101010"
    )


def test_ecb_aes():
    """
    purposely working on blocks instead of the entire input
    since we are looking to implement CBC
    """
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad

    KEY = b"YELLOW SUBMARINE"
    PLAINTEXT = b"BLACKPINK IN YOUR AREA!"
    padded_text = pad(PLAINTEXT, AES.block_size)
    encrypted_text = bytearray()
    for i in range(0, len(padded_text), AES.block_size):
        block = padded_text[i : i + AES.block_size]
        encrypted_text += ecb_aes_encrypt(block, KEY)

    decrypted_text = bytearray()
    for i in range(0, len(encrypted_text), AES.block_size):
        block = encrypted_text[i : i + AES.block_size]
        decrypted_text += ecb_aes_decrypt(block, KEY)

    unpadded_text = unpad(decrypted_text, AES.block_size)

    assert unpadded_text == PLAINTEXT
