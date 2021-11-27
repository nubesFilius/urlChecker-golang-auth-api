package usergroups

import "sync"

type Group struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members,omitempty"` //list of member user uuids
	Owners      []string `json:"owners,omitempty"`  //list of owner user uuids
}

type User struct {
	ID     string `json:"id"`
	Secret []byte `json:"hashed"`
	Email  string `json:"email"`
}

type ListGroupsResponse struct {
	Groups []Group `json:"groups"`
}

type MockDB struct {
	sync.RWMutex //inherit lock behavior
	Groups       map[string]*Group
	Users        map[string]*User
}
