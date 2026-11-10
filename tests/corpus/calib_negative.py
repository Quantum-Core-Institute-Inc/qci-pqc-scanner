# NEGATIVE: should not produce vulnerable/weak findings
# Comments and documentation
# rsa.generate_private_key is mentioned only in a comment
# MD5 is not used here

def documentation():
    text = """
    This module does not use RSA or MD5.
    Example of what not to do (commented): # hashlib.md5
    """
    return text

SAFE_ALGOS = ["SHA-256", "AES-GCM", "ChaCha20"]
