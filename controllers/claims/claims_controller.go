package claims

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"

	"encoding/json"
	"time"

	"github.com/lestrrat/go-jwx/jwk"
	"github.com/nubesFilius/urlChecker-golang-auth-api/controllers/keys"
	"github.com/nubesFilius/urlChecker-golang-auth-api/controllers/openid"
	"github.com/nubesFilius/urlChecker-golang-auth-api/controllers/usergroups"
	"github.com/nubesFilius/urlChecker-golang-auth-api/domains/claims"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
)

var (
	JWTController jwtControllerInterface = &jwtController{}
	iss           string                 = "http://localhost"
)

type jwtControllerInterface interface {
	CreateClaim(sub, aud, iss string, grps []string, lifetime time.Duration) *claims.CustomClaims
	StdClaimsToCustomClaims(stdClaims *jwt.MapClaims) (*claims.CustomClaims, error)
	GetTokenHandler(w http.ResponseWriter, r *http.Request)
	NewJWT(c *claims.CustomClaims, signingMethod jwt.SigningMethod) *jwt.Token
	SignJWT(tk *jwt.Token, key *rsa.PrivateKey) (string, error)
	ValidateJWT(tkString, iss, aud, url string, grps []string) (*claims.CustomClaims, error)
}

type jwtController struct {
}

type GetTokenResponse struct {
	Token      string `json:"token"` //Spec recommends returning in the body to avoid header size limitations
	ValidUntil int64  `json:"valid_until"`
}

// Create returns a new CustomClaims object
func (*jwtController) CreateClaim(sub, aud, iss string, grps []string, lifetime time.Duration) *claims.CustomClaims {
	return &claims.CustomClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  aud,
			ExpiresAt: time.Now().Add(lifetime).Unix(),
			Id:        uuid.Must(uuid.NewV4()).String(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    iss,
			NotBefore: time.Now().Unix(),
			Subject:   sub,
		},
		Groups: grps,
	}
}

// StdClaimsToCustomClaims populates a CustomClaims struct with a given map of std claims
func (*jwtController) StdClaimsToCustomClaims(stdClaims *jwt.MapClaims) (*claims.CustomClaims, error) {
	// marshall the std claims
	stdClaimsBytes, err := json.Marshal(stdClaims)
	if err != nil {
		return nil, err
	}
	// unmarshal onto a CustomClaims object
	var cc *claims.CustomClaims
	err = json.Unmarshal(stdClaimsBytes, cc)
	if err != nil {
		return nil, err
	}
	return cc, nil
}

//GetTokenHandler is an HTTP handler that takes in basic auth, and gives the user a JWT
func (*jwtController) GetTokenHandler(w http.ResponseWriter, r *http.Request) {
	//for now picking up basic auth but not actually using it
	username, password, ok := r.BasicAuth()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: No basic credentials provided"))
		return
	}

	if !usergroups.UserGroupsController.ValidateCredentials(username, password) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: Incorrect username or password"))
		return
	}

	userID, err := usergroups.UserGroupsController.GetUserID(username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: User passed basic auth but no records found")) //think of something better later
		return
	}

	claims := JWTController.CreateClaim(userID, "erniepy/all", iss, []string{}, time.Hour*1)

	//fill in group membership info
	claims.Groups = usergroups.UserGroupsController.GetUserMemberGroups(userID)

	//grab the signing key and id
	_, id, err := keys.KeysController.GetSigningKey()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: %s", err)) //think of something better later
		return
	}

	jwt := jwt.New(jwt.SigningMethodRS512)

	jwt.Header["sig_kid"] = id

	stringToken, err := jwt.SignedString(jwt)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: Could not sign key: %v", err)) //for now, later will want to hide
		return
	}

	respBytes, err := json.Marshal(&GetTokenResponse{
		Token:      stringToken,
		ValidUntil: claims.ExpiresAt,
	})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: Could not marshall response: %v", err)) //for now, later will want to hide
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(respBytes)) //for now, later will want to hide
	return
}

//NewJWT returns a token given claims and a specified signing method
func (*jwtController) NewJWT(c *claims.CustomClaims, signingMethod jwt.SigningMethod) *jwt.Token {
	return jwt.NewWithClaims(signingMethod, c)
}

//SignJWT signs a JSON Web Token with a given private key
func (*jwtController) SignJWT(tk *jwt.Token, key *rsa.PrivateKey) (string, error) {
	return tk.SignedString(key)
}

// ValidateJWT returns the claims within a token as a CustomClaims obect and validates its fields
func (*jwtController) ValidateJWT(tkString, iss, aud, url string, grps []string) (*claims.CustomClaims, error) {
	var cc claims.CustomClaims
	// parse onto a jwt token object. Note the in-line use of the KeyFunc type
	token, err := jwt.ParseWithClaims(tkString, cc, func(tk *jwt.Token) (interface{}, error) {
		// read the key id off the token header
		kid, ok := tk.Header["sig_kid"].(string)
		if !ok {
			return nil, errors.New("Signing Key ID Not in Token Header")
		}
		config, err := openid.OIDController.Fetch(url)
		if err != nil {
			return nil, fmt.Errorf("could not fetch openid config: %s", err)
		}
		// now get the keys from that endpoint
		keyset, err := jwk.FetchHTTP(config.KeysEndpoint)
		if err != nil {
			return nil, fmt.Errorf("Failed to get keys from the endpoint specified by the provider's discovery endpoint: %s. %v", config.KeysEndpoint, err)
		}
		// if no keys exposed, return error
		if len(keyset.Keys) < 1 {
			return nil, fmt.Errorf("No keys found from keys endpoint (%s)", config.KeysEndpoint)
		}
		// materialize the keys onto an ID to Key map
		kidtoKeyMAP := map[string]interface{}{}
		for _, key := range keyset.Keys {
			kidtoKeyMAP[key.KeyID()], err = key.Materialize()
			if err != nil {
				return nil, fmt.Errorf("Failed to materialize key %s: %s", key.KeyID(), err)
			}
		}
		// if the correct key [id matching that of the token] is found, then convert it to rsa.PublicKey
		if signersPubKey, ok := kidtoKeyMAP[kid]; ok {
			// read pemBlock bytes off map
			pubPEMData, isByteSlice := (signersPubKey).([]byte)
			if !isByteSlice {
				return nil, fmt.Errorf("Could not read bytes off public key")
			}
			// convert bytes to public key pem block
			block, _ := pem.Decode(pubPEMData)
			if block == nil || block.Type != "PUBLIC KEY" {
				return nil, fmt.Errorf("failed to decode PEM block containing public key")
			}
			// convert pem block to PubKey
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			// return the pubkey
			return pub, nil
		}
		// return error if the key of matching ID was not in found
		return nil, fmt.Errorf("No key found for the given kid")
	})
	if err != nil {
		return nil, fmt.Errorf("[ERROR] Could not parse token: %s", err)
	}
	if token == nil || !token.Valid {
		return nil, fmt.Errorf("[ERROR] Token is invalid")
	}
	// we'll only use/check HS512
	if token.Method != jwt.SigningMethodRS512 {
		return nil, fmt.Errorf("[ERROR] Signing Algorithm: %s, not supported", token.Method.Alg())
	}
	// verify text claims
	if !cc.VerifyIssuer(iss, true) {
		return nil, fmt.Errorf("[ERROR] Issuer: Expected %s but was %s", iss, cc.Issuer)
	}
	if !cc.VerifyAudience(aud, true) && aud != "" {
		return nil, fmt.Errorf("[ERROR] Audience: Expected %s but was %s", aud, cc.Audience)
	}
	// verify time claims
	now := time.Now().Unix()
	if !cc.VerifyIssuedAt(now, true) {
		return nil, fmt.Errorf("[ERROR] The token was used before \"IssuedAt\"")
	}
	if !cc.VerifyExpiresAt(now, true) {
		return nil, fmt.Errorf("[ERROR] The token is expired")
	}
	// verify group membership
	for _, grp := range grps {
		if !cc.HasGroup(grp) {
			return nil, fmt.Errorf("[ERROR] Token does not contain required group %s", grp)
		}
	}
	return &cc, nil
}
