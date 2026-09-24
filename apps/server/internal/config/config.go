package config

import (
	"errors"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// devJWTSecret is the development-only fallback; Validate rejects it in production.
const devJWTSecret = "dev-secret-change-in-production"

// minJWTSecretLen — HS256 keys shorter than the hash output (32 bytes) are weak.
const minJWTSecretLen = 32

type Config struct {
	Port string
	Env  string

	// MongoDB connection
	MongoURI string
	MongoDB  string

	// JWT signing — secret signs tokens, expiry controls how long they last
	JWTSecret        string
	JWTAccessExpiry  time.Duration
	JWTRefreshExpiry time.Duration

	// Resend email service
	ResendAPIKey string
	FromEmail    string

	// OAuth credentials from the GitHub developer console
	GithubClientID     string
	GithubClientSecret string
	GithubRedirectURL  string

	FrontendURL        string
	CORSAllowedOrigins string

	// RabbitMQ + email worker settings
	RabbitMQURL			string
	EmailMaxRetries		int
	EmailRetryDelay		time.Duration	// wait this long before each retry

	// AWS workload-identity binding: clients must sign x-lv-server-id with this value.
	AWSServerID string
}

// Load reads env vars and returns Config — call once in main()
func Load() Config {
	// Prefer monorepo path; fall back to legacy / CWD for Docker or local runs.
	_ = godotenv.Load("apps/server/.env")
	_ = godotenv.Load(".env")

	env := getEnv("ENV", "development")
	if os.Getenv("JWT_SECRET") == "" && !isProduction(env) {
		log.Println("⚠️ JWT_SECRET not set — using insecure dev fallback")
	}

	return Config{
		Port: getEnv("PORT", "8080"),
		Env:  env,

		MongoURI: getEnv("MONGODB_URI", "mongodb://localhost:27017"),
		MongoDB:  getEnv("MONGODB_DATABASE", "localvault"),

		JWTSecret:        getEnv("JWT_SECRET", devJWTSecret),
		JWTAccessExpiry:  parseDuration(getEnv("JWT_ACCESS_EXPIRY", "15m")),
		JWTRefreshExpiry: parseDuration(getEnv("JWT_REFRESH_EXPIRY", "720h")),

		ResendAPIKey: getEnv("RESEND_API_KEY", ""),
		FromEmail:    getEnv("FROM_EMAIL", "onboarding@resend.dev"),

		GithubClientID:     getEnv("GITHUB_CLIENT_ID", ""),
		GithubClientSecret: getEnv("GITHUB_CLIENT_SECRET", ""),
		GithubRedirectURL:  getEnv("GITHUB_REDIRECT_URL", "http://localhost:8080/api/v1/auth/oauth/github/callback"),

		FrontendURL:        getEnv("FRONTEND_URL", "http://localhost:3000"),
		CORSAllowedOrigins: getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000"),

		// Prefer RABBITMQ_URL; fall back to Heroku CloudAMQP's CLOUDAMQP_URL
		RabbitMQURL: getEnv("RABBITMQ_URL", getEnv("CLOUDAMQP_URL", "amqp://guest:guest@localhost:5672/")),
		EmailMaxRetries:	parseInt(getEnv("EMAIL_MAX_RETRIES", "5")),
		EmailRetryDelay: 	parseDuration(getEnv("EMAIL_RETRY_DELAY", "30s")),
		AWSServerID:        getEnv("LV_AWS_SERVER_ID", "localvault"),
	}
}

// Validate rejects unsafe settings in production — call right after Load().
func (c Config) Validate() error {
	if !isProduction(c.Env) {
		return nil
	}
	switch {
	case c.JWTSecret == "":
		return errors.New("JWT_SECRET is required in production")
	case c.JWTSecret == devJWTSecret:
		return errors.New("JWT_SECRET must not be the dev default in production")
	case len(c.JWTSecret) < minJWTSecretLen:
		return errors.New("JWT_SECRET must be at least 32 bytes in production")
	}
	return nil
}

func isProduction(env string) bool {
	return env == "production" || env == "prod"
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func parseDuration(s string) time.Duration {
	// time.ParseDuration understands "s", "m", "h" suffixes
	d, err := time.ParseDuration(s)
	if err != nil {
		return 15 * time.Minute // safe default if parsing fails
	}
	return d
}

// parseInt converts a string like "5" to int, with a safe fallback
func parseInt(s string) int {
	n, err := strconv.Atoi(s) // Atoi = ASCII to integer
	if err != nil {
		return 5 // safe default
	}
	return n
}