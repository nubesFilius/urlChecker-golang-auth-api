package application

import (
	"github.com/nubesFilius/urlChecker-golang-auth-api/controllers/claims"
	"github.com/nubesFilius/urlChecker-golang-auth-api/controllers/keys"
	"github.com/nubesFilius/urlChecker-golang-auth-api/controllers/openid"
	"github.com/nubesFilius/urlChecker-golang-auth-api/controllers/usergroups"
)

func routes() {

	// OpenId Connect Endpoint
	router.Methods("GET").Path(openid.DefaultDiscoveryPath).HandlerFunc(openid.OIDController.HTTPHandlerFunc())

	// Keystore Endpoints
	router.Methods("GET").Path("/auth/keys").HandlerFunc(keys.KeysController.SharePubKeyHandler)

	// Basic Auth Endpoints --> Emitting JWT Tokens
	router.Methods("GET").Path("/auth/login").HandlerFunc(claims.JWTController.GetTokenHandler)

	// Groups Mgmt Endpoints
	router.Methods("GET").Path("/groups").HandlerFunc(usergroups.UserGroupsController.ListGroups)
	router.Methods("GET").Path("/groups/{group_id}").HandlerFunc(usergroups.UserGroupsController.ShowGroup)
}
