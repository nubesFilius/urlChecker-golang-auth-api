package keystore

import (
	"crypto/rsa"
	"net/http"
	"time"
)

//Keystore represents an interface capable of storing and fetching public Keys
type Keystore interface {
	SetKeyPair(string, *rsa.PrivateKey, time.Duration) error
	GetPubKeys() (map[string]*rsa.PublicKey, error)
	GetSigningKey() (*rsa.PrivateKey, string, error)
	SharePubKeyHandler(http.ResponseWriter, *http.Request)
}
