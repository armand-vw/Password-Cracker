import hashlib

from passlib.hash import argon2, bcrypt, md5_crypt, nthash, sha256_crypt

from cracker import engine, hashes

WORDS = ["password", "letmein", "dragon", "P@ssw0rd"]


def run(targets, words=WORDS, rules=None, scheme=None):
    if isinstance(targets, str):
        targets = [targets]
    return engine.crack(targets, iter(words), rules or [], scheme_override=scheme)


def plaintexts(result):
    return [r["plaintext"] for r in result["results"]]


def test_md5():
    target = hashlib.md5(b"dragon").hexdigest()
    assert plaintexts(run(target)) == ["dragon"]


def test_sha256():
    target = hashlib.sha256(b"letmein").hexdigest()
    assert plaintexts(run(target)) == ["letmein"]


def test_sha512():
    target = hashlib.sha512(b"dragon").hexdigest()
    assert plaintexts(run(target)) == ["dragon"]


def test_ntlm():
    target = nthash.hash("dragon")
    assert plaintexts(run(target)) == ["dragon"]


def test_md5_crypt():
    target = md5_crypt.hash("dragon")
    assert plaintexts(run(target)) == ["dragon"]


def test_sha256_crypt():
    target = sha256_crypt.hash("dragon")
    assert plaintexts(run(target)) == ["dragon"]


def test_bcrypt():
    target = bcrypt.using(rounds=4).hash("dragon")
    assert plaintexts(run(target)) == ["dragon"]


def test_argon2():
    target = argon2.using(time_cost=1, memory_cost=1024, parallelism=1).hash("dragon")
    assert plaintexts(run(target)) == ["dragon"]


def test_batch():
    targets = [
        hashlib.md5(b"dragon").hexdigest(),
        hashlib.sha256(b"letmein").hexdigest(),
    ]
    result = run(targets)
    assert set(plaintexts(result)) == {"dragon", "letmein"}
    assert len(result["results"]) == 2


def test_rules_uppercase():
    target = hashlib.sha256(b"DRAGON").hexdigest()
    assert plaintexts(run(target, rules=["upper"])) == ["DRAGON"]


def test_rules_append():
    target = hashlib.md5(b"dragon123").hexdigest()
    result = run(target, rules=["append"])
    assert "dragon123" in plaintexts(result)


def test_scheme_override():
    target = nthash.hash("dragon")
    result = run(target, scheme="ntlm")
    assert result["results"][0]["scheme"] == "ntlm"


def test_auto_detect_ambiguous():
    target = hashlib.md5(b"dragon").hexdigest()
    names = {s.name for s in hashes.detect_all(target)}
    assert "md5" in names
    assert "ntlm" in names


def test_apply_rules_dedup():
    variants = engine.apply_rules("dragon", ["lower", "capitalize", "append"])
    assert len(variants) == len(set(variants))
    assert "dragon123" in variants
