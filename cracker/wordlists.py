"""Wordlist loading helpers."""


def iter_words(path):
    """Yield one stripped, decoded word per line from a wordlist file."""
    with open(path, "rb") as f:
        for raw in f:
            line = raw.rstrip(b"\r\n")
            if not line:
                continue
            try:
                text = line.decode("utf-8")
            except UnicodeDecodeError:
                text = line.decode("latin-1", errors="replace")
            text = text.strip()
            if text:
                yield text
