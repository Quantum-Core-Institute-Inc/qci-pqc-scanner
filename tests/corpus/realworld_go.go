// Go real-world style (CIRCL + stdlib)
package main

import (
    "crypto/rsa"
    "crypto/ecdsa"
    "github.com/cloudflare/circl/kem/mlkem"
    "github.com/cloudflare/circl/sign/mldsa"
)

func classical() {
    rsa.GenerateKey(nil, 2048)
    ecdsa.GenerateKey(nil, nil)
}

func pqc() {
    _ = mlkem.Scheme()
    _ = mldsa.Mode65
}
