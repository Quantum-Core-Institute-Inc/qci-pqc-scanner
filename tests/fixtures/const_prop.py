HASH_ALG = "sha1"
KEY_ALG = "DSA"

def fingerprint(blob):
    import hashlib
    return hashlib.new(HASH_ALG)

def make_key():
    return KEY_ALG
