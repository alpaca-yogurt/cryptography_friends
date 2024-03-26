import random
from cryptopals.utils import cbc_aes_encrypt, ecb_aes_encrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

if __name__ == "__main__":
    """
    ECB/CBC detection oracle
    1. Write a function that generates a random AES key (random 16 bytes)
    2. Write a function that pads the start and end of the plaintext with 5-10 bytes (count is random).
    3. Write a function that encrypts the padded plaintext with ECB or CBC (chosen randomly)
    """

    def unsecure_generate_random_bytes(length: int) -> bytes:
        """
        UNSECURE
        Generate random bytes of specified length
        """
        key = bytes([random.randint(0, 255) for _ in range(length)])
        return key

    def add_random_padding(buffer: bytes) -> bytes:
        """
        Pad both ends of a buffer with random bytes (count chosen randomly [5,10])
        """
        start = unsecure_generate_random_bytes(random.randint(5, 10))
        end = unsecure_generate_random_bytes(random.randint(5, 10))
        return start + buffer + end

    def encrypt_ecb_or_cbc_aes(buffer: bytes) -> dict[str, str | bytes]:
        cbc = random.randint(0, 1)
        buffer = pad(add_random_padding(buffer), AES.block_size)
        blocks = [buffer[i : i + AES.block_size] for i in range(0, len(buffer), AES.block_size)]
        if cbc:
            b = cbc_aes_encrypt(
                blocks=blocks,
                key=unsecure_generate_random_bytes(AES.block_size),
                iv=unsecure_generate_random_bytes(AES.block_size),
            )
            return {"ciphertext": b, "mode": "cbc"}
        else:
            b = bytes()
            key = unsecure_generate_random_bytes(AES.block_size)
            for block in blocks:
                b += ecb_aes_encrypt(block, key)
            return {"ciphertext": b, "mode": "ecb"}

    def ecb_cbc_detection_oracle():
        # Extract
        oracle_input = b'0' * (11 + AES.block_size*2)
        out = encrypt_ecb_or_cbc_aes(oracle_input)
        ciphertext = out['ciphertext']
        mode = out['mode']
        blocks = [ciphertext[i:i+AES.block_size] for i in range(0, len(ciphertext), AES.block_size)]
        block_count = len(blocks)
        unique_block_count = len(set(blocks))
        if block_count != unique_block_count:
            assert mode == 'ecb'
            return 'ecb'
        else:
            assert mode == 'cbc'
            return 'cbc'


    for _ in range(10):
        ecb_cbc_detection_oracle()
