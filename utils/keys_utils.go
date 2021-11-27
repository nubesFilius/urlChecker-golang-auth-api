package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

//RSAPublicKeyToPEM Converts an RSA PubKey to its PEM representation
func RSAPublicKeyToPEM(pubKey *rsa.PublicKey) ([]byte, error) {
	asn1Bytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	return pem.EncodeToMemory(block), nil
}
