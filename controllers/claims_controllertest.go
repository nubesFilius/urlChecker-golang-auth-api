package controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/adrianosela/auth/cjwt"

	cli "gopkg.in/urfave/cli.v1"
)

func JWTTest() {

	app := cli.NewApp()
	app.EnableBashCompletion = true
	app.Usage = "JWT Validation CLI"
	app.CommandNotFound = func(c *cli.Context, command string) {
		fmt.Println("[ERROR] The command provided is not supported: ", command)
		c.App.Run([]string{"help"})
	}

	app.Commands = []cli.Command{
		{
			Name:   "validate",
			Usage:  "Validate a given JWT",
			Action: validate,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "jwt",
					Usage: "The JWT itself",
				},
				cli.StringFlag{
					Name:  "iss",
					Usage: "The domain of the JWT issuer",
				},
				cli.StringFlag{
					Name:  "authprov",
					Usage: "The endpoint we wish to use for checking openID config", //default will be = issuer
				},
				cli.StringFlag{
					Name:  "aud",
					Usage: "The JWT's target audience",
				},
				cli.StringFlag{
					Name:  "grps",
					Usage: "Comma separated groups",
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func validate(ctx *cli.Context) error {
	groupString := ctx.String("grps")
	tkString := ctx.String("jwt")
	iss := ctx.String("iss")
	authProviderEndpoint := ctx.String("authprov")

	if tkString == "" || iss == "" {
		return errors.New("jwt and iss are required flags")
	}

	if authProviderEndpoint == "" {
		authProviderEndpoint = iss
	}

	aud := ctx.String("aud")

	grps := strings.Split(groupString, ",")
	if groupString == "" { // split function returns 1 empty string if an empty string is split
		grps = []string{}
	}

	cc, err := cjwt.ValidateJWT(tkString, iss, aud, authProviderEndpoint, grps)
	if err != nil {
		return fmt.Errorf("[ERROR] Could not validate JWT: %s", err)
	}

	jsonbytes, err := json.Marshal(cc)
	if err != nil {
		return fmt.Errorf("[ERROR] Could not marshall custom claims: %s", err)
	}

	fmt.Println(string(jsonbytes))
	return nil
}
