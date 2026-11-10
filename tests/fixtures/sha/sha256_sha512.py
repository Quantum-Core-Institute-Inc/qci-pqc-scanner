import hashlib
from cryptography.hazmat.primitives import hashes

hashlib.sha256(b"a").hexdigest()
hashlib.sha512(b"a").hexdigest()
hashlib.new("sha256", b"a").hexdigest()
hashlib.new("sha512", b"a").hexdigest()
hashes.SHA256()
hashes.SHA512()
