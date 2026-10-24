// Package config loads and validates runtime configuration from environment variables.
//
// SECURITY: All secrets (DB credentials, JWT signing secret, AES key) come from the
// environment, never from source code. The server refuses to start if a secret is
// missing or too weak ("fail fast / secure by default").
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"health-metrics-vault/crypto"
)

type Config struct {
	Port           string
	DBDSN          string
	JWTSecret      []byte
	JWTIssuer      string
	JWTTTL         time.Duration
	AESKey         string
	AllowedOrigins []string
	GinMode        string
}

// minJWTSecretLen: HS256 secrets shorter than the hash output (32 bytes) are
// brute-forceable offline once an attacker obtains any token.
const minJWTSecretLen = 32

func Load() (*Config, error) {
	cfg := &Config{
		Port:      getEnv("PORT", "8080"),
		DBDSN:     os.Getenv("DB_DSN"),
		JWTSecret: []byte(os.Getenv("JWT_SECRET")),
		JWTIssuer: getEnv("JWT_ISSUER", "health-metrics-vault"),
		AESKey:    os.Getenv("AES_ENCRYPTION_KEY"),
		GinMode:   getEnv("GIN_MODE", "release"),
	}

	if cfg.DBDSN == "" {
		return nil, errors.New("DB_DSN is required")
	}
	if len(cfg.JWTSecret) < minJWTSecretLen {
		return nil, fmt.Errorf("JWT_SECRET must be at least %d characters", minJWTSecretLen)
	}
	if err := crypto.ValidateKey(cfg.AESKey); err != nil {
		return nil, fmt.Errorf("AES_ENCRYPTION_KEY: %w", err)
	}

	ttl, err := time.ParseDuration(getEnv("JWT_TTL", "1h"))
	if err != nil || ttl <= 0 || ttl > 24*time.Hour {
		return nil, errors.New("JWT_TTL must be a positive duration <= 24h (e.g. 1h, 30m)")
	}
	cfg.JWTTTL = ttl

	for _, o := range strings.Split(getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			if o == "*" {
				return nil, errors.New("CORS_ALLOWED_ORIGINS must list explicit origins, '*' is not allowed")
			}
			cfg.AllowedOrigins = append(cfg.AllowedOrigins, o)
		}
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
