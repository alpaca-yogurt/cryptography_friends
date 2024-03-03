import cryptopals.utils as utils

"""
Set 1
Challenge 3
Score plaintext generated from single character XOR on target string
"""

if __name__ == "__main__":
    t = utils.get_scored_text(bytearray.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
    for n, line in enumerate(t):
        if n == 5:
            break
        print(line)
