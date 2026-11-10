"""Additional hash algorithms."""
import hashlib

hashlib.sha224(b"a").hexdigest()
hashlib.sha384(b"a").hexdigest()
hashlib.sha3_384(b"a").hexdigest()
hashlib.sha3_512(b"a").hexdigest()
hashlib.shake_128(b"a").hexdigest(16)
hashlib.shake_256(b"a").hexdigest(32)
hashlib.new("ripemd160", b"a").hexdigest()
