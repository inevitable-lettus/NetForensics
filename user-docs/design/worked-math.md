# Worked math

The two statistics the detectors use, by hand, so you can check any finding yourself.

## Shannon entropy

Entropy measures how unpredictable the characters of a string are. For each distinct
character, take its share `p` of the string; then

```text
H = -( p1·log2(p1) + p2·log2(p2) + ... )        bits per character
```

| String | Characters | Calculation | H |
|---|---|---|---|
| `aaaa` | one character, `p = 1` | `-(1·log2 1)` | 0 |
| `aabb` | `a` and `b`, `p = 1/2` each | `-(½·log2 ½ + ½·log2 ½)` | 1 |
| `abcd` | four, `p = 1/4` each | `-4·(¼·log2 ¼)` | 2 |
| `images` | `i, m, a, g, e, s`, `p = 1/6` each | `log2 6` | 2.585 |

Entropy never exceeds `log2(number of distinct characters)`, and so never exceeds
`log2(length)`. Encoded or random data uses many characters about equally, so it sits near that
ceiling; ordinary words repeat letters and sit lower (the baseline here is 2.5).

**Why a long subdomain is needed.** The cutoff is 4.2 bits. `2^4.2 = 18.4`, so a string needs at
least 19 distinct characters, and therefore at least 19 characters, to reach it at all. A
short encoded label can never trip the entropy cutoff. That is a known gap, listed in
[Known limitations](../help/known-limitations.md).

The detector takes the **highest** entropy among the subdomains under one parent domain.

## Coefficient of variation (beaconing)

The gaps between consecutive connections are `g1, g2, ...`. Then

```text
CV = sample standard deviation of the gaps / mean of the gaps
```

The sample standard deviation divides by `n - 1`, because the gaps are a sample of a longer
behaviour, not all of it.

### A beacon with jitter that still fires

Gaps in seconds: `60, 63, 57, 66, 54, 61, 59, 64, 56` (nine gaps, ten connections).

- Mean: `540 / 9 = 60`
- Deviations from the mean: `0, 3, -3, 6, -6, 1, -1, 4, -4`
- Sum of squares: `0 + 9 + 9 + 36 + 36 + 1 + 1 + 16 + 16 = 124`
- Sample variance: `124 / 8 = 15.5`, standard deviation `3.94`
- **CV = 3.94 / 60 = 0.066**, below 0.1: fires.

### Jitter large enough to evade

Gaps: `42, 78, 51, 66, 45, 72, 58, 63, 84, 55`.

- Mean: `614 / 10 = 61.4`
- Sum of squared deviations: `1728.4`
- Sample variance: `1728.4 / 9 = 192.0`, standard deviation `13.86`
- **CV = 13.86 / 61.4 = 0.226**, above 0.1: does not fire.

The same average gap, a different spread. An operator who adds enough random delay beats this
rule; the evidence sentence prints the exact CV so a person can still judge borderline cases.

## Port-scan fan-out

Order the source's connections by time. Slide a 10-second window across them and, at each
position, count distinct destination ports and distinct destination hosts. The two maxima are
kept separately: one window may have the most ports and another the most hosts. A finding
needs the port maximum at or above 100 or the host maximum at or above 10.

## DNS query rate

```text
rate = queries / duration of the flow in seconds × 60
```

The sample capture's 120 queries span 59.5 seconds, so the rate is `120 / 59.5 × 60 = 121.0`
queries per 60 s, which is what the evidence sentence in the [quick start](../getting-started/quick-start.md)
shows ("scaled to a 60 s window from 120 queries in total"). A flow of zero duration, such as a
single packet, uses the raw count.
