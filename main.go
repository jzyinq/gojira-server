package main

import (
	"encoding/json"
	"fmt"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	missingIdentifierMsg    = "Missing identifier"
	missingCodeMsg          = "Missing code"
	failedTokenExchangeMsg  = "Failed to exchange token"
	failedJSONResponseMsg   = "Failed to create JSON response"
	authorizationSuccessMsg = "Authorization successful. You can close this window."
)

type Config struct {
	OAuth2Config oauth2.Config
}

type TokenStore struct {
	store map[string]*oauth2.Token
	mu    sync.Mutex
}

func NewTokenStore() *TokenStore {
	return &TokenStore{store: make(map[string]*oauth2.Token)}
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request: %s %s", r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

func handleStart(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identifier := r.URL.Query().Get("identifier")
		if identifier == "" {
			http.Error(w, missingIdentifierMsg, http.StatusBadRequest)
			return
		}

		authURL := cfg.OAuth2Config.AuthCodeURL(identifier, oauth2.AccessTypeOffline)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func handleCallback(cfg *Config, tokenStore *TokenStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, missingCodeMsg, http.StatusBadRequest)
			return
		}

		identifier := r.URL.Query().Get("state")
		token, err := cfg.OAuth2Config.Exchange(r.Context(), code)
		if err != nil {
			fmt.Printf("Unable to retrieve token from web: %v\n", err)
			http.Error(w, failedTokenExchangeMsg, http.StatusInternalServerError)
			return
		}

		if identifier != "" {
			tokenStore.mu.Lock()
			tokenStore.store[identifier] = token
			tokenStore.mu.Unlock()
		}

		w.Write([]byte(authorizationSuccessMsg))
	}
}

func handleTokenFetch(tokenStore *TokenStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identifier := r.URL.Query().Get("identifier")
		if identifier == "" {
			http.Error(w, missingIdentifierMsg, http.StatusBadRequest)
			return
		}

		tokenStore.mu.Lock()
		token, found := tokenStore.store[identifier]
		tokenStore.mu.Unlock()

		if !found {
			http.Error(w, "Identifier not found", http.StatusNotFound)
			return
		}

		tokenJSON, err := json.Marshal(token)
		if err != nil {
			http.Error(w, failedJSONResponseMsg, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(tokenJSON)
	}
}

func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	cfg := &Config{
		OAuth2Config: oauth2.Config{
			ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
			ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("OAUTH_REDIRECT_URL"),
			Scopes:       []string{os.Getenv("OAUTH_SCOPE")},
			Endpoint:     google.Endpoint,
		},
	}

	tokenStore := NewTokenStore()

	http.Handle("/start", LoggingMiddleware(http.HandlerFunc(handleStart(cfg))))
	http.Handle("/callback", LoggingMiddleware(http.HandlerFunc(handleCallback(cfg, tokenStore))))
	http.Handle("/fetch_token", LoggingMiddleware(http.HandlerFunc(handleTokenFetch(tokenStore))))

	log.Fatal(http.ListenAndServe(":"+os.Getenv("HTTP_PORT"), nil))
}
