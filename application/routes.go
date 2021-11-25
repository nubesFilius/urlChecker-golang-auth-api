package application

import (
	"github.com/nubesFilius/urlChecker-golang-auth-api/domains/openid"
)

type Configuration struct {
	OpenID *openid.DiscoveryConfig
}

var conf Configuration

func mapUrls() {

	// OpenId Connect Endpoint
	router.Methods("GET").Path(openid.DefaultDiscoveryPath).HandlerFunc(conf.OpenID.HTTPHandlerFunc())

	router.Methods("GET").Path("/auth/keys").HandlerFunc(conf.Keystore.SharePubKeyHandler)

}
