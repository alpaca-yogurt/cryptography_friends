import base64


def hex_to_base64(_hex: bytearray) -> bytearray:
    match _hex:
        case bytearray():
            pass
        case _:
            raise ValueError("hex_to_base64 only accepts bytearrays")

    return bytearray(base64.b64encode(_hex))


def fixed_xor(b1: bytearray, b2: bytearray) -> bytearray:
    if len(b1) != len(b2):
        raise ValueError(f"fixed_xor requires buffers of the same length")

    match (b1, b2):
        case [bytearray(), bytearray()]:
            return bytearray(i ^ v for i, v in zip(b1, b2))
        case _:
            raise ValueError(f"fixed_xor requires the buffers to be bytearrays")


def get_bytearray_of_all_characters() -> bytearray:
    return bytearray(range(32, 127))


def single_byte_xor(single_character_key: int, buffer: bytearray) -> bytearray:
    match single_character_key, buffer:
        case [int(), bytearray()]:
            return bytearray(b ^ single_character_key for b in buffer)
        case _:
            raise ValueError("single_byte_xor requires an int representing your key and a bytearray")


def score_english_text(text: str) -> int:
    """
    ETAOIN SHRDLU
    where we total all the counts and then multiply that value by the number of characters that were used
    """
    characters_of_interest_dict = dict.fromkeys(list("etaoin shrdlu"), 0)
    for c in text.lower():
        if c in characters_of_interest_dict:
            characters_of_interest_dict[c] += 1
    count = sum(1 for v in characters_of_interest_dict.values() if v != 0)
    total = sum(v for v in characters_of_interest_dict.values())
    return count * total


def repeating_key_xor(key: bytearray, buffer: bytearray) -> bytearray:
    from itertools import cycle as c

    cycle = c(key)
    return bytearray(b ^ next(cycle) for b in buffer)


def hamming_distance(s1: bytearray, s2: bytearray) -> int:
    """
    Hamming distance is defined as the difference in bits by the authors of the challenge.
    With that in mind, we can calculate the difference by XORing each byte
    then we can construct a string that represents the bits that includes zero padding.
    Finally, we just count the 1s to determine the difference.
    """
    match s1, s2:
        case [bytearray(), bytearray()]:
            bits = (b1 ^ b2 for b1, b2 in zip(s1, s2))
            return "".join((bin(b)[2:].zfill(8) for b in bits)).count('1')
        case _:
            raise ValueError("str_hamming_distance only takes in 2 bytearrays")

