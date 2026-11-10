import os
HASH_ALG = os.environ.get("APP_DIGEST", "SHA1")
def go():
    return HASH_ALG
