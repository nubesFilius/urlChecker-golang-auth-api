package claims

import "github.com/dgrijalva/jwt-go"

// CustomClaims represents claims we wish to make and verify with JWTs
type CustomClaims struct {
	jwt.StandardClaims
	Groups []string `json:"grps,omitempty"`
}

// HasGroup returns true if a CustomClaims object contains a given group as part of its grp claims
func (cc *CustomClaims) HasGroup(groupID string) bool {
	for _, grp := range cc.Groups {
		if grp == groupID {
			return true
		}
	}
	return false
}
