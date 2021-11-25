package openid

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/pkg/errors"
)

const DefaultDiscoveryPath = "/.well-known/webfinger"

type DiscoveryConfig struct {
	Issuer                                     string   `json:"issuer"`
	AuthEndpoint                               string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserInfoEndpoint                           string   `json:"userinfo_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	KeysEndpoint                               string   `json:"jwks_uri"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValues                    []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
}

func DefaultDiscoveryConfig(url string) *DiscoveryConfig {
	return &DiscoveryConfig{
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

func Fetch(url string) (*DiscoveryConfig, error) {
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

	var discoveryConfig DiscoveryConfig
	err = json.Unmarshal(respBytes, &discoveryConfig)
	if err != nil {
		return nil, fmt.Errorf("bad type / could not parse OpenID configuration: %s", err)
	}
	return &discoveryConfig, nil
}

// HTTPHandlerFunc returns an HTTP handler function for
// the OpenID Discovery Configuration to be served at
func (dc *DiscoveryConfig) HTTPHandlerFunc() http.HandlerFunc {
	configBytes, err := json.Marshal(&dc)
	if err != nil {
		panic(errors.Wrap(err, "could not marshal OpenID Connect Discovery Configuration"))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, string(configBytes))
		return
	})
}
