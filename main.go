package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"time"

	"github.com/gofrs/uuid"
	"github.com/nubesFilius/urlChecker-golang-auth-api/application"
	"github.com/nubesFilius/urlChecker-golang-auth-api/controllers/keys"
	"github.com/nubesFilius/urlChecker-golang-auth-api/utils"
)

func main() {
	application.StartApplication()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("[ERROR] Could not generate keys")
	}
	block, err := utils.RSAPublicKeyToPEM(&key.PublicKey)
	if err != nil {
		log.Fatal("[ERROR] Could not convert key to PEM")
	}
	id := uuid.Must(uuid.NewV4()).String()
	log.Printf("[INFO] Generated New Key-Pair: {\"id\":\"%s\"}\n%s", id, string(block))

	err = keys.KeysController.SetKeyPair(id, key, time.Duration(time.Hour*12))
	if err != nil {
		log.Fatalf("[ERROR] Could not set Key: %v", err)
	}
}
