if __name__ == "__main__":
    """
    This works because ECB is stateless and deterministic,
    given a sufficiently large ciphertext that was encrypted with ECB will have at least one repeating block
    """
    with open("set1_8.in", "r") as f:
        # 16 -> 128 bits
        # 20 -> length of each ciphertext is 320, 320//16 = 20
        block_sets = (set(c[n * 16 : (n + 1) * 16] for n in range(20)) for c in [line.strip() for line in f])
        for i, b in enumerate(block_sets):
            if len(b) < 20:
                print(i, b)
