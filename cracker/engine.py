"""Dictionary attack engine."""
import time

from .hashes import detect_all, get_scheme

COMMON_SUFFIXES = [
    "1", "12", "123", "1234", "12345", "123456",
    "!", "!!", "@",
    "2026", "2025", "2024", "2023", "2022", "2021", "2020",
    "2019", "2000", "1990", "007", "69",
]

_LEET_TABLE = str.maketrans(
    {
        "a": "4", "A": "4",
        "e": "3", "E": "3",
        "i": "1", "I": "1",
        "o": "0", "O": "0",
        "s": "5", "S": "5",
        "t": "7", "T": "7",
    }
)


def leet(word):
    return word.translate(_LEET_TABLE)


def apply_rules(word, rules):
    """Return the list of candidate variants for a word, de-duplicated."""
    variants = [word]
    if "lower" in rules:
        variants.append(word.lower())
    if "upper" in rules:
        variants.append(word.upper())
    if "capitalize" in rules:
        variants.append(word.capitalize())
    if "leet" in rules:
        variants.append(leet(word))
    if "reverse" in rules:
        variants.append(word[::-1])
    if "append" in rules:
        variants.extend(word + s for s in COMMON_SUFFIXES)

    seen = set()
    out = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def crack(target_hashes, word_iter, rules, scheme_override=None,
          on_progress=None, should_stop=None):
    """Crack ``target_hashes`` using a dictionary attack.

    Returns a dict with ``results`` (list of dicts), ``tried`` (candidate
    count) and ``elapsed`` (seconds).
    """
    unsalted = {}   # scheme name -> {normalized digest: original hash}
    salted = []     # list of (scheme, target hash)

    for raw in target_hashes:
        target = raw.strip()
        if not target:
            continue
        schemes = [get_scheme(scheme_override)] if scheme_override else detect_all(target)
        for scheme in schemes:
            if scheme.salted:
                salted.append((scheme, target))
            else:
                unsalted.setdefault(scheme.name, {})[target.lower()] = target

    results = []
    tried = 0
    last_emit = 0
    start = time.time()

    for word in word_iter:
        if should_stop is not None and should_stop():
            break
        for variant in apply_rules(word, rules):
            tried += 1

            for name, digest_map in unsalted.items():
                scheme = get_scheme(name)
                digest = scheme.hash(variant)
                if digest in digest_map:
                    results.append({
                        "hash": digest_map[digest],
                        "plaintext": variant,
                        "scheme": name,
                    })

            for scheme, target in salted:
                if scheme.verify(variant, target):
                    results.append({
                        "hash": target,
                        "plaintext": variant,
                        "scheme": scheme.name,
                    })

            if on_progress is not None and tried - last_emit >= 500:
                on_progress(tried, len(results))
                last_emit = tried

    if on_progress is not None:
        on_progress(tried, len(results))

    return {"results": results, "tried": tried, "elapsed": time.time() - start}
