package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/captncraig/easyauth"
	"github.com/captncraig/easyauth/providers/ldap"
	"github.com/captncraig/easyauth/providers/token"
)

// roles are binary flags. Set up however you like.
const (
	CanRead easyauth.Role = 1 << iota
	CanComment
	CanModerate
	CanEdit
	RoleCommenter = CanRead | CanComment
	RoleEditor    = RoleCommenter | CanEdit
	RoleModerator = RoleEditor | CanModerate
)

func main() {
	auth, err := easyauth.New(
		easyauth.CookieSecret("RQnAGDB4LWINpyJDxAKtEwk91uB3J0CZoeWtueUBc7f8rRE+Ulv1vYJ37Z2zK+5PK2WZ58IqQvH+87+5kOSiNw=="),
	)
	if err != nil {
		log.Fatal(err)
	}

	l := &ldap.LdapProvider{
		LdapAddr:          "ds.myorg.com:3269",
		AllowInsecure:     true,
		DefaultPermission: CanRead,
		RootSearchPath:    "DC=ds,DC=myorg,DC=com",
		Domain:            "MYORG",
		Groups: []*ldap.LdapGroup{
			{
				Path: "CN=Developers,OU=Security Groups,DC=ds,DC=myorg,DC=com",
				Role: RoleCommenter,
			},
		},
		Users: map[string]easyauth.Role{
			"cpeterson": RoleModerator,
		},
	}
	auth.AddProvider("ldap", l)

	store, err := token.NewJsonStore("tokens.json")
	if err != nil {
		log.Fatal(err)
	}
	tok := token.NewToken("askdjlkasd", store)
	auth.AddProvider("token", tok)

	//only admins can manage auth tokens
	http.Handle("/api/tokens", auth.Wrap(tok.AdminHandler(), RoleModerator))

	http.Handle("/login/", http.StripPrefix("/login", auth.LoginHandler()))

	http.Handle("/", auth.Wrap(render("Hello, this does not require auth"), 0))
	http.Handle("/edit", auth.Wrap(render("edit stuff"), CanEdit))
	http.Handle("/comment", auth.Wrap(render("comment page"), CanComment))

	http.ListenAndServe(":8080", nil)
}

func render(s string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := easyauth.GetUser(r)
		loggedIn := ""
		if u == nil {
			loggedIn = "Not logged in. <a href='/login'>Log in</login>"
		} else {
			loggedIn = fmt.Sprintf("Logged in as %s. <a href='/login/out'>Log out</a>", u.Username)
			loggedIn += "<hr/>Permissions:<ul>"
			possible := map[string]easyauth.Role{
				"Read":     CanRead,
				"Comment":  CanComment,
				"Edit":     CanEdit,
				"Moderate": CanModerate,
			}
			for name, perm := range possible {
				if u.Access&perm != 0 {
					loggedIn += fmt.Sprintf("<li>%s</li>", name)
				}
			}
		}
		w.Write([]byte("<html><body>" + s + "<hr/>" + loggedIn))
	})
}
