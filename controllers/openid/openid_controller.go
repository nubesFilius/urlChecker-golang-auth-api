package openid

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/nubesFilius/urlChecker-golang-auth-api/domains/openid"
	"github.com/pkg/errors"
)

const DefaultDiscoveryPath = "/.well-known/webfinger"

var (
	OIDController oidControllerInterface = &oidController{}
)

type oidControllerInterface interface {
	DefaultDiscoveryConfig(url string) *openid.DiscoveryConfig
	Fetch(url string) (*openid.DiscoveryConfig, error)
	HTTPHandlerFunc() http.HandlerFunc
}

type oidController struct {
}

func (*oidController) DefaultDiscoveryConfig(url string) *openid.DiscoveryConfig {
	return &openid.DiscoveryConfig{
		Issuer:                            url,
		AuthEndpoint:                      url + "/auth",
		TokenEndpoint:                     url + "/auth/token",
		UserInfoEndpoint:                  url + "/auth/userinfo",
		KeysEndpoint:                      url + "/auth/keys",
		ScopesSupported:                   []string{"openid"},
		ResponseTypesSupported:            []string{"code", "id_token", "token id_token"},
		ResponseModesSupported:            []string{"query", "fragment"},
		GrantTypesSupported:               []string{"refresh_token"},
		SubjectTypesSupported:             []string{"pairwise"},
		IDTokenSigningAlgValues:           []string{"RS512"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"RS512"},
		ClaimsSupported: []string{"aud", "exp", "jti", "iat", "iss", "sub", "grps"},
	}
}

// Get request to the DefaultDiscoveryPath url of OIDC
func (*oidController) Fetch(url string) (*openid.DiscoveryConfig, error) {
	resp, err := http.Get(fmt.Sprintf("%s%s", url, DefaultDiscoveryPath))
	if err != nil {
		return nil, fmt.Errorf("could not fetch OpenID Configuration: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad response from discovery endpoint HTTP: %d", resp.StatusCode)
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read body of discovery endpoint response: %s", err)
	}
	defer resp.Body.Close()

	var discoveryConfig openid.DiscoveryConfig
	err = json.Unmarshal(respBytes, &discoveryConfig)
	if err != nil {
		return nil, fmt.Errorf("bad type / could not parse OpenID configuration: %s", err)
	}
	return &discoveryConfig, nil
}

// HTTPHandlerFunc returns an HTTP handler function for
// the OpenID Discovery Configuration to be served at
func (oid *oidController) HTTPHandlerFunc() http.HandlerFunc {
	configBytes, err := json.Marshal(&oid)
	if err != nil {
		panic(errors.Wrap(err, "could not marshal OpenID Connect Discovery Configuration"))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, string(configBytes))
		return
	})
}
