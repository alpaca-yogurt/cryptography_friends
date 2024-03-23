import base64
from Crypto.Cipher import AES

from cryptopals.utils import recursive_cbc_solve, cbc_solve

KEY = b"YELLOW SUBMARINE"
IV = b"\x00" * 16

if __name__ == "__main__":
    with open("set2_10.in", "r") as f:
        b = bytearray()
        for line in f:
            b += base64.b64decode(line.rstrip())

        # blocks of size AES.block_size
        blocks = [b[i : i + AES.block_size] for i in range(0, len(b), AES.block_size)]

    a = recursive_cbc_solve(bytes(), blocks, KEY, IV)
    b = cbc_solve(blocks, KEY, IV)
    assert a == b
