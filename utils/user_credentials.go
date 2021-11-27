package utils

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode"
)

func EmailIsValid(email string) error {
	// TODO: add more error validation
	_, err := mail.ParseAddress((email))
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	return nil
}

// adding simple password validation for
func PasswordIsValid(password string) error {
	characters := 0
	letters := 0
	var number, upper, special bool
	for _, c := range password {
		switch characters++; {
		case unicode.IsNumber(c):
			number = true
		case unicode.IsUpper(c):
			upper = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			special = true
		case unicode.IsLetter(c) || c == ' ':
			letters++
		default:
			number = false
			upper = false
			special = false
		}
	}

	allMessages := []string{}
	switch {
	case !number:
		allMessages = append(allMessages, "no number")
	case !upper:
		allMessages = append(allMessages, "no uppercase")
	case !special:
		allMessages = append(allMessages, "no special character")
	case letters < 7:
		allMessages = append(allMessages, "no minimum of letters")
	case characters < 12:
		allMessages = append(allMessages, "no minimum length")
	}
	if len(allMessages) > 0 {
		return fmt.Errorf(
			"insecure password: %v",
			strings.Join(allMessages, ", "),
		)
	}
	return nil
}
