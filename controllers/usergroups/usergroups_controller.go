package usergroups

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/gofrs/uuid"
	"github.com/gorilla/mux"
	"github.com/nubesFilius/urlChecker-golang-auth-api/domains/usergroups"
	"github.com/nubesFilius/urlChecker-golang-auth-api/utils"
	"golang.org/x/crypto/bcrypt"
)

var (
	UserGroupsController userGroupsInterface = &userGroupsController{}
	db                   *usergroups.MockDB
)

type userGroupsController struct {
}

//Datastore will allow us to implement a database in multiple ways
type userGroupsInterface interface {
	// AddGroup will add a new group to the database
	AddGroup(*usergroups.Group) error

	// DeleteGroup will remove a group given its group id
	DeleteGroup(string) error

	// AddUserToGroup will add a user of a given id to a group of given id
	AddUserToGroup(string, string, string) error

	// RemoveUserFromGroup will remove a user of a given id from a group of given id
	RemoveUserFromGroup(string, string, string) error

	// AddUser will add a new user to the database given username, password, and email, returns the ID
	AddUser(string, string, string) (string, error)

	// GetUserID gets a user's ID given their username
	GetUserID(string) (string, error)

	// DeleteUser will remove a user from the database
	DeleteUser(string) error

	// HTTP Endpoint Handler for listing groups
	ListGroups(http.ResponseWriter, *http.Request)

	// HTTP Endpoint Handler for showing a group
	ShowGroup(http.ResponseWriter, *http.Request)

	ValidateCredentials(string, string) bool
	GetUserMemberGroups(string) []string
}

//NewMockDB returns a new MockDB
func (*userGroupsController) NewMockDB() *usergroups.MockDB {
	return &usergroups.MockDB{
		Groups: map[string]*usergroups.Group{},
		Users:  map[string]*usergroups.User{},
	}
}

//GetUserID returns the user ID of a user given his/her username
func (*userGroupsController) GetUserID(uname string) (string, error) {
	db.RLock()
	defer db.RUnlock()
	//if found return the id, else error
	if user, ok := db.Users[uname]; ok {
		return user.ID, nil
	}
	return "", fmt.Errorf("Username %s not in store", uname)
}

//PassedBasicAuth takes in basic auth credentials, hashes the password and compares against the hash in store
func (*userGroupsController) ValidateCredentials(uname, pass string) bool {
	db.RLock()
	defer db.RUnlock()

	if user, ok := db.Users[uname]; ok {
		if err := bcrypt.CompareHashAndPassword(user.Secret, []byte(pass)); err == nil {
			return true
		}
		return false
	}
	return false
}

//addGroup will add a new group to the database
func (*userGroupsController) AddGroup(gp *usergroups.Group) error {
	db.Lock()
	defer db.Unlock()
	//add the group to the map
	db.Groups[gp.ID] = gp
	log.Printf("[MOCK_DB] Added New Group: {\"name\":\"%s\",\"id\":\"%s\"}", gp.Name, gp.ID)
	// TODO add error handling
	return nil
}

//DeleteGroup will remove a group given its group id
func (*userGroupsController) DeleteGroup(id string) error {
	db.Lock()
	defer db.Unlock()
	//if the entry exists delete its value
	if _, ok := db.Groups[id]; ok {
		delete(db.Groups, id)
		log.Printf("[MOCK_DB] Deleted Group: {\"id\":\"%s\"}", id)
		return nil
	}
	//if not found
	return errors.New("Group with id=%d not found in store")
}

// AddUserToGroup will add a user of a given id to a group of given id
func (*userGroupsController) AddUserToGroup(userID, groupID, membershipType string) error {
	db.Lock()
	defer db.Unlock()
	//check userID is not empty
	if userID == "" {
		return errors.New("Empty user id")
	}
	//if the entry exists then add the user
	if grp, ok := db.Groups[groupID]; ok {
		if membershipType == "OWNER" {
			grp.Owners = append(grp.Owners, userID)
			log.Printf("[MOCK_DB] Added User: {\"id\":\"%s\"} as an OWNER to Group: {\"id\":\"%s\"}", userID, groupID)
			return nil
		}
		if membershipType == "MEMBER" {
			grp.Members = append(grp.Members, userID)
			log.Printf("[MOCK_DB] Added User: {\"id\":\"%s\"} as a MEMBER to Group: {\"id\":\"%s\"}", userID, groupID)
			return nil
		}
		return fmt.Errorf("Invalid membership type specified: %s", membershipType)
	}
	//if group not found
	return fmt.Errorf("Group with id=%s not found in store", groupID)
}

//removeUserFromGroup will remove a user of a given id from a group of given id
func (*userGroupsController) RemoveUserFromGroup(userID, groupID, membershipType string) error {
	db.Lock()
	defer db.Unlock()
	//check userID is not empty
	if userID == "" {
		return errors.New("Empty user id")
	}
	var err error
	//if the entry exists then remove the user
	if grp, ok := db.Groups[groupID]; ok {
		if membershipType == "OWNER" {
			grp.Owners, err = utils.RemoveStrFromSlice(groupID, grp.Owners)
			if err == nil {
				log.Printf("[MOCK_DB] Removed User: {\"id\":\"%s\"} as an OWNER to Group: {\"id\":\"%s\"}", userID, groupID)
			}
			return err
		}
		if membershipType == "MEMBER" {
			grp.Members, err = utils.RemoveStrFromSlice(groupID, grp.Members)
			if err == nil {
				log.Printf("[MOCK_DB] Removed User: {\"id\":\"%s\"} as a MEMBER to Group: {\"id\":\"%s\"}", userID, groupID)
			}
			return err
		}
		return fmt.Errorf("Invalid membership type specified: %s", membershipType)
	}
	//if group not found
	return fmt.Errorf("Group with id=%s not found in store", groupID)
}

// AddUser will add a new user to the database
func (*userGroupsController) AddUser(username, password, email string) (string, error) {
	if err := utils.EmailIsValid(email); err != nil {
		return err.Error(), err
	}
	if err := utils.PasswordIsValid(password); err != nil {
		return err.Error(), err
	}
	usr := &usergroups.User{
		Email: email,
		ID:    uuid.Must(uuid.NewV4()).String(),
	}

	passbytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("[ERROR] Could not hash password, user %s was not added", username)
	}

	usr.Secret = passbytes
	log.Printf("[DEBUG] user: %s, password: %s", username, password)

	//add the user to the map of username to user object
	db.Lock()
	db.Users[username] = usr
	db.Unlock()

	log.Printf("[MOCK_DB] Added New User: {\"uname\":\"%s\",\"id\":\"%s\"}", username, usr.ID)
	return usr.ID, nil
}

//deleteUser will remove a user from the database
func (*userGroupsController) DeleteUser(id string) error {
	db.Lock()
	defer db.Unlock()
	//if the entry exists then delete it
	if _, ok := db.Users[id]; ok {
		delete(db.Users, id)
		log.Printf("[MOCK_DB] Deleted User: {\"id\":\"%s\"} from DB", id)
		return nil
	}
	//if user not found
	return fmt.Errorf("User with id=%s not found in store", id)
}

//ListGroups is an HTTP Req. Handler that lists groups in the database
func (*userGroupsController) ListGroups(w http.ResponseWriter, r *http.Request) {
	db.RLock() //note this could be more fine grained
	defer db.RUnlock()

	grps := []usergroups.Group{}
	for id, grp := range db.Groups {
		grps = append(grps, usergroups.Group{
			ID:          id,
			Name:        grp.Name,
			Description: grp.Description,
		})
	}

	respBytes, err := json.Marshal(&usergroups.ListGroupsResponse{
		Groups: grps,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, fmt.Sprintf("[ERROR]: Could not marshall response: %v", err)) //for now, later will want to hide
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, string(respBytes))
	return
}

//ShowGroup is an HTTP Req. Handler that lists groups in the database
func (*userGroupsController) ShowGroup(w http.ResponseWriter, r *http.Request) {
	db.RLock() //could be more finegrained
	defer db.RUnlock()

	vars := mux.Vars(r)

	if gid, ok := vars["group_id"]; ok {
		respBytes, err := json.Marshal(&usergroups.Group{
			Name:    db.Groups[gid].Name,
			ID:      db.Groups[gid].ID,
			Members: db.Groups[gid].Members,
			Owners:  db.Groups[gid].Owners,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError) //for now
			fmt.Fprint(w, string("Could not marhall response"))
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, string(respBytes))
		return
	}
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, string("Group not found")) //for now, later will want to hide
	return
}

func (*userGroupsController) GetUserMemberGroups(userid string) []string {
	db.RLock()
	defer db.RUnlock()
	memberOf := []string{}
	for groupid, grp := range db.Groups {
		if utils.WordInSlice(userid, grp.Members) {
			memberOf = append(memberOf, groupid)
		}
	}
	return memberOf
}
