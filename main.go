package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/imsilence/nsqdauth/identity"

	"github.com/imsilence/nsqdauth/session"
)

func main() {
	var (
		addr string
		db   string
		help bool
		h    bool
	)
	flag.StringVar(&addr, "addr", ":9999", "listen addr")
	flag.StringVar(&db, "db", "identity.csv", "identity csv db")
	flag.BoolVar(&help, "help", false, "help")
	flag.BoolVar(&h, "h", false, "help")

	flag.Usage = func() {
		fmt.Println("Usage: auth --addr :9999 --db identity.csv")
		flag.PrintDefaults()
	}

	flag.Parse()

	if h || help {
		flag.Usage()
		os.Exit(0)
	}
	identities, err := identity.ParseIdentity(db)
	if err != nil {
		log.Fatal(err)
	}

	session := session.NewSession()

	http.HandleFunc("/secret", func(w http.ResponseWriter, r *http.Request) {
		var form struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&form); err == nil {
			log.Println("secret request:", form.Username)
			if err, identity := identities.Valid(form.Username, form.Password); err == nil {
				secret := session.Set(identity)
				log.Println("secret response:", form.Username, secret)
				json.NewEncoder(w).Encode(struct {
					Secret string `json:"secret"`
				}{secret})
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
	})

	http.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		// remoteAddr := r.FormValue("remote_ip")
		// tls := r.FormValue("tls")
		secret := r.FormValue("secret")
		log.Println("secret request:", secret)
		// commonName := r.FormValue("common_name")
		if ident, err := session.Get(secret); err == nil {
			state := struct {
				TTL            int                      `json:"ttl"`
				Authorizations []identity.Authorization `json:"authorizations"`
				Identity       string                   `json:"identity"`
				IdentityURL    string                   `json:"identity_url"`
			}{
				TTL:            24 * 60 * 60,
				Authorizations: ident.Authorizations,
				Identity:       ident.Username,
				IdentityURL:    fmt.Sprintf("http://%s/secret", addr),
			}

			log.Println("secret response:", secret, state)

			json.NewEncoder(w).Encode(state)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	})

	log.Fatal(http.ListenAndServe(addr, nil))
}
