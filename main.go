package main

import (
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"log"
	"net/http"
	"os"
	"sync"
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

func handleMain() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.String(http.StatusOK, "Simple OAuth Proxy")
	}
}

func handleStart(cfg *Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		identifier := c.DefaultQuery("identifier", "")
		if identifier == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": missingIdentifierMsg})
			return
		}
		authURL := cfg.OAuth2Config.AuthCodeURL(identifier, oauth2.AccessTypeOffline)
		c.Redirect(http.StatusFound, authURL)
	}
}

func handleCallback(cfg *Config, tokenStore *TokenStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		code := c.DefaultQuery("code", "")
		if code == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": missingCodeMsg})
			return
		}

		identifier := c.DefaultQuery("state", "")
		token, err := cfg.OAuth2Config.Exchange(c, code)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": failedTokenExchangeMsg})
			return
		}

		if identifier != "" {
			tokenStore.mu.Lock()
			tokenStore.store[identifier] = token
			tokenStore.mu.Unlock()
		}

		c.String(http.StatusOK, authorizationSuccessMsg)
	}
}

func handleTokenFetch(tokenStore *TokenStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		identifier := c.DefaultQuery("identifier", "")
		if identifier == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": missingIdentifierMsg})
			return
		}

		tokenStore.mu.Lock()
		token, found := tokenStore.store[identifier]
		tokenStore.mu.Unlock()

		if !found {
			c.JSON(http.StatusNotFound, gin.H{"error": "Identifier not found"})
			return
		}

		c.JSON(http.StatusOK, token)
	}
}

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Print("No .env file detected - using existing env variables.")
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

	r := gin.Default()

	r.GET("/", handleMain())
	r.GET("/start", handleStart(cfg))
	r.GET("/callback", handleCallback(cfg, tokenStore))
	r.GET("/fetch_token", handleTokenFetch(tokenStore))

	port := os.Getenv("HTTP_PORT")
	if port == "" {
		port = "8080" // Default port
	}
	r.Run(":" + port)
}
