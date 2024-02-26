import cryptopals.utils as utils

"""
Set 1
Challenge 3
Score plaintext generated from single character XOR on target string
"""


def get_scored_text(target: bytearray) -> list[tuple[chr, str, int]]:
    chars = utils.get_bytearray_of_all_characters()
    scored_text = [
        (chr(key), out := utils.single_byte_xor(key, target).decode(errors="ignore"), utils.score_english_text(out))
        for key in chars
    ]
    scored_text.sort(key=lambda score: score[2], reverse=True)
    return scored_text


if __name__ == "__main__":
    t = get_scored_text(bytearray.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
    for n, line in enumerate(t):
        if n == 5:
            break
        print(line)
