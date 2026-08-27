from __future__ import annotations
from collections import Counter
import math


def shannon_entropy(text: str) -> float:
    """Returning bits per char"""
    if not text:
        return 0.0
    counts = Counter(text)
    H = 0.0
    n = len(text)
    for count in counts.values():
        p = count / n 
        H -= p * math.log2(p)

    return H
