package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// For demonstration, using an in-memory map to store tokens. In production, use a database.
var (
	tokenStore = make(map[string]*oauth2.Token)
	mu         sync.Mutex
)

var oauth2Config = oauth2.Config{
	ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
	RedirectURL:  os.Getenv("OAUTH_REDIRECT_URL"),
	Scopes:       []string{os.Getenv("OAUTH_SCOPE")},
	Endpoint:     google.Endpoint,
}

func handleStart(w http.ResponseWriter, r *http.Request) {
	identifier := r.URL.Query().Get("identifier")
	if identifier == "" {
		http.Error(w, "Missing identifier", http.StatusBadRequest)
		return
	}

	authURL := oauth2Config.AuthCodeURL(identifier, oauth2.AccessTypeOffline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}

	identifier := r.URL.Query().Get("state")
	token, err := oauth2Config.Exchange(r.Context(), code)
	if err != nil {
		fmt.Printf("Unable to retrieve token from web: %v", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	if identifier != "" {
		mu.Lock()
		tokenStore[identifier] = token
		mu.Unlock()
	}

	w.Write([]byte("Authorization successful. You can close this window."))
}

func handleTokenFetch(w http.ResponseWriter, r *http.Request) {
	identifier := r.URL.Query().Get("identifier")
	if identifier == "" {
		http.Error(w, "Missing identifier", http.StatusBadRequest)
		return
	}

	mu.Lock()
	token, found := tokenStore[identifier]
	mu.Unlock()

	if !found {
		http.Error(w, "Identifier not found", http.StatusNotFound)
		return
	}

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		http.Error(w, "Failed to create JSON response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(tokenJSON)
}

func main() {
	http.HandleFunc("/start", handleStart)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/fetch_token", handleTokenFetch)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
