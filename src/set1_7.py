import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

KEY = b"YELLOW SUBMARINE"


if __name__ == "__main__":
    with open("set1_7.in", "r") as f:
        b = bytearray()
        for line in f:
            b += base64.b64decode(line.rstrip())
        cipher = AES.new(KEY, AES.MODE_ECB)
        message = unpad(cipher.decrypt(b), AES.block_size)
        print(message.decode())
