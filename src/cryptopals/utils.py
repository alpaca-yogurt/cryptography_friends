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
            return bytearray([i ^ v for i, v in zip(b1, b2)])
        case _:
            raise ValueError(f"fixed_xor requires the buffers to be bytearrays")
