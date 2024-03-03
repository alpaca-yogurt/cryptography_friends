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
    Consider the most common characters but also have
    negative weights for characters that are not found in English text
    """
    most_common_letters = set("etaoin shrdlu")
    other_letters = set("mqywzjkvpbcxfg")
    numbers = set("0123456789")
    punctuation = set("',.?!;\":")
    special_chars = set("^~\\=@}>[&-$%/]|+_{(*`<)#")
    score = 0
    for c in text.lower():
        if c in most_common_letters:
            score += 10
        elif c in other_letters:
            score += 2
        elif c in numbers or c in punctuation:
            score += 1
        elif c in special_chars:
            pass
        else:
            # other ascii indicates the string is probably not English
            score -= 10

    return score


def get_scored_text(target: bytearray) -> list[tuple[chr, str, int]]:
    """
    all character single xor, basically setup so we can find the key
    """
    chars = get_bytearray_of_all_characters()
    scored_text = [(chr(key), out := single_byte_xor(key, target).decode(), score_english_text(out)) for key in chars]
    scored_text.sort(key=lambda score: score[2], reverse=True)
    return scored_text


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
            return "".join((bin(b)[2:].zfill(8) for b in bits)).count("1")
        case _:
            raise ValueError("str_hamming_distance only takes in 2 bytearrays")


def solve_repeating_key_xor(
    buffer: bytearray, min_key_size: int = 2, max_key_size: int = 40, keys_to_try: int = 20
) -> bytearray:
    """
    Uses the best key of the key size that had the smallest hamming distance
    """

    def calculate_edit_distance(b: bytearray, ks: int, blocks: int = 10) -> float:
        h = [hamming_distance(b[ks * n : ks * (n + 1)], b[ks * (n + 1) : ks * (n + 2)]) / ks for n in range(blocks)]
        return sum(h) / len(h)

    def transpose_blocks(b: bytearray, ks: int) -> list[bytearray]:
        """
        Given a buffer, return a list of blocks of key size where each block contains the nth element of each block
        of key size of the cipher text
        """
        blocks = [b[i : i + ks] for i in range(0, len(b), ks)]
        # pad last block if it doesn't match the length of the key size we want
        blocks[-1] = blocks[-1].zfill(ks)
        return [bytearray(block) for block in zip(*blocks)]

    # calculate the hamming distances for key sizes in the given range
    # sort them in ascending order
    distance_dict = {i: calculate_edit_distance(buffer, i) for i in range(min_key_size, max_key_size + 1)}
    distance_dict = dict(sorted(distance_dict.items(), key=lambda item: item[1], reverse=False))
    min_distances = {k: v for i, (k, v) in enumerate(distance_dict.items()) if i < keys_to_try}
    keys = []
    for d in min_distances.keys():
        bs = transpose_blocks(buffer, d)
        scored_text = [get_scored_text(b) for b in bs]
        key = ""
        for text in scored_text:
            key += text[0][0]
        keys.append(bytearray(key.encode()))

    print(keys)
    for n, key in enumerate(keys, start=1):
        print(n, repeating_key_xor(key, buffer))

    return repeating_key_xor(keys[0], buffer)
