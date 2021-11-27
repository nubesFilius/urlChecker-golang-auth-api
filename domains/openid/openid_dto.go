package openid

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
