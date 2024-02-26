import set1_3

"""
Set 1
Challenge 4
Detect single character XOR
"""


def detect_single_character_xor() -> None:
    answers = []
    with open("set1_4.in", "r") as f:
        for n, line in enumerate(f, 1):
            _answers = [
                (i, f"Line: {n}", line.rstrip()) for i in set1_3.get_scored_text(bytearray.fromhex(line.rstrip()))
            ]
            answers.append(_answers)
    top_scores = [a[0] for a in answers]
    top_scores.sort(key=lambda score: score[0][2], reverse=True)
    for n, s in enumerate(top_scores):
        if n == 5:
            break
        print(s)


if __name__ == "__main__":
    detect_single_character_xor()
