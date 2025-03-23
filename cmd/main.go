package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	oidc "github.com/coreos/go-oidc"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

var Config oauth2.Config

// load env vars cfg
func init() {
	viper.AutomaticEnv()
}

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	http.HandleFunc("/", HandleLogin)
	http.HandleFunc("/auth/callback", HandleCallback)
	log.Fatal(http.ListenAndServe(viper.GetString("HTTP_PORT"), nil)) 

				
}


	
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, viper.GetString("OIDC_ISSUER"))
	if err != nil {
		panic(err)
	}	

	Config := oauth2.Config{
		ClientID:     viper.GetString("OIDC_CLIENT_ID"),
		ClientSecret: viper.GetString("OIDC_CLIENT_SECRET"),
		RedirectURL:  viper.GetString("OIDC_REDIRECT_URL"),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "roles"},		
	}
	state := viper.GetString("OIDC_PK_STATE")

	http.Redirect(w, r, Config.AuthCodeURL(state), http.StatusFound) 

}	
func HandleCallback(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("state") != viper.GetString("OIDC_PK_STATE") {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}

	oauth2Token, err :=  Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Println(oauth2Token)

	rawlIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in oauth2 token", http.StatusInternalServerError)
		return
	}
	fmt.Println("====================================")
	fmt.Println(rawlIDToken)
	
	resp := struct {
		OAuth2Token *oauth2.Token
		RawIDToken  string
	}{
		OAuth2Token: oauth2Token, RawIDToken: rawlIDToken,
	}

	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)	
	}




	w.Write(data)

}
