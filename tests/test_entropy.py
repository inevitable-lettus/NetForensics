from __future__ import annotations

import math

from backend.parse.entropy import shannon_entropy


def test_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_single_repeated_char_is_zero():
    # No uncertainty — every char is the same symbol.
    assert shannon_entropy("aaaaaa") == 0.0


def test_two_symbols_equal_split_is_one_bit():
    # p=0.5/0.5 -> H = -(0.5*log2(0.5) + 0.5*log2(0.5)) = 1.0
    assert math.isclose(shannon_entropy("abab"), 1.0)


def test_four_distinct_symbols_uniform_is_two_bits():
    # 4 symbols, uniform -> H = log2(4) = 2.0
    assert math.isclose(shannon_entropy("abcd"), 2.0)


def test_high_entropy_random_looking_subdomain_exceeds_low_entropy_word():
    benign = shannon_entropy("wwwwww")
    random_like = shannon_entropy("a8f3k2z9")
    assert random_like > benign
