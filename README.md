# Password Cracker

[![CI](https://github.com/armand-vw/Password-Cracker/actions/workflows/ci.yml/badge.svg)](https://github.com/armand-vw/Password-Cracker/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A self-hosted Flask web application that recovers plaintext passwords from
**hashes** using a dictionary attack. Built as an educational security project
demonstrating hash algorithms, password cracking techniques, and why strong
passwords matter.

> **Legal & ethical use only.** This tool performs *offline* cracking of hashes
> you own or are authorized to test. Do not use it against systems or data you
> do not own.

<img width="1917" height="873" alt="Screenshot 1" src="https://github.com/user-attachments/assets/7d7ef24b-c38c-46d8-9b13-2cc0632be736" />

<img width="1918" height="881" alt="Screenshot 2" src="https://github.com/user-attachments/assets/bade2078-2bd3-4924-9f38-258cd818e2c6" />



## Features

- **Dictionary attack** over any wordlist (built-in sample included, or
  upload/paste your own).
- **40+ hash formats** with automatic detection, or select one explicitly.
- **Batch cracking** — paste many hashes; each candidate is hashed once and
  compared against every target in a single pass.
- **Mangling rules** — lowercase, uppercase, capitalize, leet-speak, reverse,
  and append common digits/years.
- **Background jobs** — cracking runs in a worker thread while the UI polls for
  live progress, so the page never blocks.

## Quickstart

```bash
pip install -r requirements.txt
python3 app.py
```

Open **http://localhost:5001** in your browser.

> The port is set to `5001` to avoid conflicts with common dev ports. Change
> `PORT` at the top of `app.py` if needed.

## Usage

1. Paste one or more hashes (one per line).
2. Choose a wordlist: the built-in sample, an uploaded file, or pasted words.
3. Pick a hash type (or leave **Auto-detect**) and enable any mangling rules.
4. Click **Crack** and watch the live progress and results.

## Supported hash formats

| Category | Formats |
|---|---|
| Raw digests | md5, sha1, sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, blake2b, blake2s |
| Windows | ntlm, lm |
| Unix crypt | md5_crypt (`$1$`), sha1_crypt, sha256_crypt (`$5$`), sha512_crypt (`$6$`), apr_md5_crypt (`$apr1$`), des_crypt, bsdi_crypt, bsd_nthash, sun_md5_crypt |
| Password KDFs | bcrypt (`$2a$/2b$/2y$`), bcrypt_sha256, argon2, pbkdf2_sha1/256/512, phpass |
| Databases | mysql323, mysql41, mssql2000, cisco_pix |
| LDAP | ldap_md5, ldap_sha1, ldap_salted_md5/sha1/sha256/sha512 |

Formats that look identical (e.g. 32 hex characters is both MD5 and NTLM) are
ambiguous; auto-detect tries every plausible scheme, or select one manually to
disambiguate.

## Project structure

```
.
├── app.py                  # Flask app + job management (port 5001)
├── cracker/
│   ├── hashes.py           # 40+ hash schemes: detection + verification
│   ├── engine.py           # dictionary attack core + mangling rules
│   └── wordlists.py        # wordlist loading
├── templates/index.html    # single-page UI
├── static/style.css
├── wordlists/common-sample.txt
├── tests/test_engine.py
├── requirements.txt
└── pyproject.toml
```

## How it works

For each word in the wordlist, the engine applies the selected mangling rules,
computes the candidate hash **once**, and compares it against all target hashes
(batch optimization). Salted formats (bcrypt, argon2, crypt) are verified
per-target since their salt is embedded in the hash.

## Testing

```bash
python -m pytest -q
```

## Honest limitations

- Dictionary attacks only find passwords present in (or mangles of) the
  wordlist; truly random passwords are not recoverable.
- Fast hashes (MD5/SHA) crack quickly; bcrypt/argon2 are intentionally slow.
- Jobs are held in memory and are lost on restart.

## License

[MIT](LICENSE) © 2026 armand-vw
