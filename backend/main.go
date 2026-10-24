// Health Metrics Vault - secure medical records API.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"health-metrics-vault/config"
	"health-metrics-vault/database"
	"health-metrics-vault/handlers"
	"health-metrics-vault/middleware"
	"health-metrics-vault/models"
)

func main() {
	// Local development convenience: load .env if present. In Docker/production the
	// variables are injected by the environment and no .env file exists.
	_ = godotenv.Load()          // .env in the current directory
	_ = godotenv.Load("../.env") // .env in the repo root when running from backend/

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	gin.SetMode(cfg.GinMode)

	db, err := database.Connect(cfg.DBDSN)
	if err != nil {
		log.Fatalf("database: %v", err)
	}

	h, err := handlers.New(db, cfg)
	if err != nil {
		log.Fatalf("handlers: %v", err)
	}

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: setupRouter(cfg, h),
		// SECURITY: timeouts mitigate Slowloris-style DoS (gosec G112).
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	go func() {
		log.Printf("Health Metrics Vault listening on :%s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server: %v", err)
		}
	}()

	// Graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

func setupRouter(cfg *config.Config, h *handlers.Handler) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery()) // Recovery: panics -> 500 without leaking stack traces

	// Do not trust X-Forwarded-For from arbitrary clients (IP spoofing).
	if err := r.SetTrustedProxies(nil); err != nil {
		log.Fatalf("trusted proxies: %v", err)
	}

	r.Use(
		middleware.CORS(cfg.AllowedOrigins),
		middleware.SecurityHeaders(),
		middleware.BodyLimit(1<<20), // 1 MiB
	)

	r.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })

	api := r.Group("/api")

	// Public Mini-IAM endpoints.
	auth := api.Group("/auth")
	auth.POST("/register", h.Register)
	auth.POST("/login", h.Login)

	// Everything below requires a valid JWT.
	protected := api.Group("")
	protected.Use(middleware.AuthMiddleware(cfg.JWTSecret, cfg.JWTIssuer))

	patientOnly := middleware.RequireRole(models.RolePatient)

	// RBAC: only patients can create records and manage consent.
	protected.POST("/records", patientOnly, h.CreateRecord)
	protected.POST("/access", patientOnly, h.GrantAccess)
	protected.DELETE("/access/:doctor_id", patientOnly, h.RevokeAccess)

	// Both roles may call this; object-level authorization (IDOR) is enforced in the handler.
	protected.GET("/records/:patient_id", middleware.RequireRole(models.RolePatient, models.RoleDoctor), h.GetRecords)

	return r
}
