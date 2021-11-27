package keys

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	kapi "github.com/nubesFilius/keystore-golang-api/api"
	keys "github.com/nubesFilius/urlChecker-golang-auth-api/utils"
	jose "github.com/square/go-jose"
)

var (
	RestKeyStoreUrl = "http://localhost"
)

var (
	KeysController keysControllerInterface = &keysController{}
)

//Keystore represents an interface capable of storing and fetching public Keys
type keysControllerInterface interface {
	NewRestKeystore() (*keysController, error)
	SetKeyPair(string, *rsa.PrivateKey, time.Duration) error
	GetKeyIds() ([]string, error)
	GetPubKeys() (map[string]*rsa.PublicKey, error)
	GetSigningKey() (*rsa.PrivateKey, string, error)
	GetKeyMetadata(keyID string) (*kapi.KeyMetadata, error)
	SharePubKeyHandler(http.ResponseWriter, *http.Request)
	RefreshCache() error
}

//RESTKeystore is a client of my own REST keystore found in github.com/adrianosela/Keystore
type keysController struct {
	sync.RWMutex //inherit read/write lock behavior
	HTTPClient   http.Client
	CachedKeys   map[string]*kapi.KeyMetadata `json:"keys"`
	SigningKey   *rsa.PrivateKey
	SigningKeyID string
}

//NewRestKeystore returns the addr of a new keystore object
func (kc *keysController) NewRestKeystore() (*keysController, error) {
	ks := &keysController{
		HTTPClient: http.Client{
			Timeout: time.Duration(time.Second * 15),
		},
		CachedKeys: map[string]*kapi.KeyMetadata{},
	}
	err := ks.RefreshCache()
	if err != nil {
		return nil, fmt.Errorf("Could not refresh the cached keys. %s", err)
	}
	return ks, nil
}

//SetKeyPair will cache a given key locally as well as publish it to the RestKeystore
func (kc *keysController) SetKeyPair(keyID string, keyPair *rsa.PrivateKey, lifespan time.Duration) error {
	if keyPair == nil {
		return fmt.Errorf("[ERROR] Could not set key: Key was nil, key_id = %s", keyID)
	}
	//grab and defer release of write lock
	kc.Lock()
	defer kc.Unlock()
	kc.SigningKey = keyPair
	kc.SigningKeyID = keyID
	//convert the key to PEM
	pemKey, err := keys.RSAPublicKeyToPEM(&keyPair.PublicKey)
	if err != nil {
		return fmt.Errorf("Could not convert key: %s, to pem. %s", keyID, err)
	}
	//put it in the KeyMetadata struct
	keyMeta := kapi.KeyMetadata{
		ID:           keyID,
		InvalidAfter: time.Now().Add(lifespan),
		KeyPem:       pemKey,
	}
	//marshall onto JSON bytes
	jsonKeyMeta, err := json.Marshal(keyMeta)
	if err != nil {
		return fmt.Errorf("Could not marshall key: %s. %s", keyID, err)
	}
	//create the http request
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/key", RestKeyStoreUrl), bytes.NewBuffer(jsonKeyMeta))
	if err != nil {
		return fmt.Errorf("Could not create POST request to RESTKeystore API for key: %s. %s", keyID, err)
	}
	//send it over the Keystore's HTTPClient
	resp, err := kc.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("Could not send POST request to RESTKeystore API for key: %s. %s", keyID, err)
	}
	//if the POST succeeded, then save to the local cache
	if resp.StatusCode == http.StatusOK {
		kc.CachedKeys[keyID] = &keyMeta
		return nil
	}
	return fmt.Errorf("POST to RESTKeystore was not successful. Status Code = %d", resp.StatusCode)
}

//  Get Public Key from Cache
func (kc *keysController) GetPubKeys() (map[string]*rsa.PublicKey, error) {
	err := kc.RefreshCache()
	if err != nil {
		return nil, fmt.Errorf("Could not refresh the cached keys. %s", err)
	}
	//respecting the return type in my keystore interface
	keysMap := make(map[string]*rsa.PublicKey)
	//Grab the read lock
	kc.RLock()
	defer kc.RUnlock()
	//convert every PEM key in the cache to RSA and stick it in the map
	for id, key := range kc.CachedKeys {
		rsakey, err := jwt.ParseRSAPublicKeyFromPEM(key.KeyPem)
		if err != nil {
			return nil, err
		}
		keysMap[id] = rsakey
	}
	return keysMap, nil
}

func (kc *keysController) RefreshCache() error {
	kc.Lock()
	defer kc.Unlock()
	//get all the IDs of all the keys on the store server
	RESTkeystoreIDs, err := kc.GetKeyIds()
	if err != nil {
		return fmt.Errorf("Could not get the list of IDs in store. %s", err)
	}
	//for every key that we know is in store, we check if its cached
	for _, id := range RESTkeystoreIDs {
		//if the key is not found in the cache
		if _, ok := kc.CachedKeys[id]; !ok {
			log.Printf("[INFO] Pulling Key From REST Keystore: %s\n", id)
			keyMeta, err := kc.GetKeyMetadata(id)
			if err != nil {
				log.Printf("[ERROR] Could not pull Key From REST Keystore: %s\n. %s", id, err)
				continue //graceful failure means we just forget about that key for now
			}
			kc.CachedKeys[id] = keyMeta
			log.Printf("[INFO] Pulled Key From REST Keystore: %s\n", id)
		}
	}
	//clean up expired Keys
	kc.retireExpired()
	return nil
}

func (kc *keysController) GetKeyMetadata(keyID string) (*kapi.KeyMetadata, error) {
	//create the http request to get the Key
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/key/%s", RestKeyStoreUrl, keyID), nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create GET request to RESTKeystore API. %s", err)
	}

	retries := 0
	err = errors.New("")
	//we will attempt to get the key three times
	for err != nil && retries < 3 {
		resp, err := kc.HTTPClient.Do(req)
		retries++
		if err != nil {
			continue
		}
		//read the response bytes if success
		jsonBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		var keyMeta kapi.KeyMetadata
		err = json.Unmarshal(jsonBytes, &keyMeta)
		if err != nil {
			continue
		}
		return &keyMeta, nil
	}
	return nil, fmt.Errorf("3 Failed attempts at getting key %s from RESTKeystore. %s", keyID, err)
}

func (kc *keysController) GetKeyIds() ([]string, error) {
	//create request
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/keys", RestKeyStoreUrl), nil)
	if err != nil {
		return nil, errors.New("Could not create GET request for keys")
	}
	//send the request
	resp, err := kc.HTTPClient.Do(req)
	if err != nil {
		return nil, errors.New("Could not send GET request for keys")
	}
	defer resp.Body.Close()
	//read the bytes off the body
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("Could not read response for keys")
	}
	//unmarshall onto a type dictated by the keystore API
	var list kapi.GetKeyListOutput
	err = json.Unmarshal(respBytes, &list)
	if err != nil {
		return nil, err //errors.New("Could not unmashall keystore list response")
	}
	return list.KeyIDList, nil
}

//GetSigningKey returns the signing key along with its ID
func (kc *keysController) GetSigningKey() (*rsa.PrivateKey, string, error) {
	kc.RLock()
	defer kc.RUnlock()
	if kc.SigningKey == nil || kc.SigningKeyID == "" {
		return nil, "", errors.New("No Signing Key Set")
	}
	return kc.SigningKey, kc.SigningKeyID, nil
}

func (kc *keysController) SharePubKeyHandler(w http.ResponseWriter, r *http.Request) {
	if err := kc.RefreshCache(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR] : %v", err))
		return
	}

	keyset := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{},
	}

	for kid, key := range kc.CachedKeys {
		keyset.Keys = append(keyset.Keys, jose.JSONWebKey{
			Key:       key.KeyPem,
			Algorithm: "RS512",
			Use:       "sig",
			KeyID:     kid,
		})
	}

	keysBytes, err := json.Marshal(keyset)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR] : %v", err))
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(keysBytes))
	return
}

// TODO
func (kc *keysController) retireExpired() {
	//TODO
}
