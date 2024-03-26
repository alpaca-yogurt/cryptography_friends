import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from cryptopals.utils import recursive_cbc_aes_decrypt, cbc_aes_decrypt, cbc_aes_encrypt, recursive_cbc_aes_encrypt

KEY = b"YELLOW SUBMARINE"
IV = b"\x00" * 16

if __name__ == "__main__":
    with open("set2_10.in", "r") as f:
        _b = bytearray()
        for line in f:
            _b += base64.b64decode(line.rstrip())

        # blocks of size AES.block_size
        blocks = [_b[i : i + AES.block_size] for i in range(0, len(_b), AES.block_size)]

        a = recursive_cbc_aes_decrypt(bytes(), blocks, KEY, IV)
        b = cbc_aes_decrypt(blocks, KEY, IV)
        assert a == b
        b = pad(b, AES.block_size)
        blocks = [b[i : i + AES.block_size] for i in range(0, len(b), AES.block_size)]
        cipher_text = cbc_aes_encrypt(blocks, KEY, IV)
        c2 = recursive_cbc_aes_encrypt(bytes(), blocks, KEY, IV)
        assert cipher_text == _b
        assert _b == c2
