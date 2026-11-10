package main

import (
    "crypto/md5"
    "crypto/rsa"
    "crypto/sha1"
)

func example() {
    rsa.GenerateKey(nil, 2048)
    md5.New()
    sha1.New()
}
