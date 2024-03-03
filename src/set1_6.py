from cryptopals import utils
import base64


def main() -> None:
    with open("set1_6.in", "r") as f:
        b = bytearray()
        for line in f:
            b += base64.b64decode(line.rstrip())
        msg = utils.solve_repeating_key_xor(b, keys_to_try=5)
        print(msg)


if __name__ == "__main__":
    main()
