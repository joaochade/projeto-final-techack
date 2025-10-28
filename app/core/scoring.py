def label_from_score(score: int) -> str:
    if score < 30: return "Seguro"
    if score < 70: return "Suspeito"
    return "Malicioso"