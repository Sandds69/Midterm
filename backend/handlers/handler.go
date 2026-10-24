// Package handlers implements the HTTP API of Health Metrics Vault.
package handlers

import (
	"health-metrics-vault/config"
	"health-metrics-vault/crypto"

	"gorm.io/gorm"
)

// Handler holds shared dependencies for all HTTP handlers.
type Handler struct {
	DB  *gorm.DB
	Cfg *config.Config

	// dummyHash is compared against when a login email does not exist, so the
	// response time is the same as for a wrong password (prevents user enumeration
	// via timing side channel).
	dummyHash string
}

func New(db *gorm.DB, cfg *config.Config) (*Handler, error) {
	dummy, err := crypto.HashPassword("timing-attack-mitigation-dummy-password")
	if err != nil {
		return nil, err
	}
	return &Handler{DB: db, Cfg: cfg, dummyHash: dummy}, nil
}
