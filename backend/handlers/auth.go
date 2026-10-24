package handlers

import (
	"errors"
	"log"
	"net/http"
	"net/mail"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"health-metrics-vault/crypto"
	"health-metrics-vault/middleware"
	"health-metrics-vault/models"
)

type registerRequest struct {
	Email    string      `json:"email" binding:"required,email,max=255"`
	Password string      `json:"password" binding:"required,min=8,max=72"`
	Role     models.Role `json:"role" binding:"required"`
}

type loginRequest struct {
	Email    string `json:"email" binding:"required,email,max=255"`
	Password string `json:"password" binding:"required,max=72"`
}

// Register handles POST /api/auth/register.
//
// SECURITY:
//   - Input validation (email format, password length 8..72, role allow-list).
//   - Password is bcrypt-hashed before storage; plaintext is never persisted or logged.
//   - Only 'patient' or 'doctor' can be chosen; there is no way to self-assign an
//     admin/other role (prevents privilege escalation via mass assignment).
//     NOTE: in production, doctor accounts would require out-of-band license verification.
func (h *Handler) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: email, password (8-72 chars) and role are required"})
		return
	}
	if !req.Role.Valid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be 'patient' or 'doctor'"})
		return
	}
	email := normalizeEmail(req.Email)
	if _, err := mail.ParseAddress(email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email"})
		return
	}

	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid password"})
		return
	}

	user := models.User{Email: email, PasswordHash: hash, Role: req.Role}
	if err := h.DB.Create(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
			return
		}
		log.Printf("register: db error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// PasswordHash is excluded from JSON via the `json:"-"` tag on the model.
	c.JSON(http.StatusCreated, gin.H{"id": user.ID, "email": user.Email, "role": user.Role})
}

// Login handles POST /api/auth/login and returns a signed JWT.
//
// SECURITY:
//   - Same generic error for "unknown email" and "wrong password" -> no user enumeration.
//   - When the user does not exist we still run bcrypt against a dummy hash so the
//     response time does not reveal whether the email is registered.
func (h *Handler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var user models.User
	err := h.DB.Where("email = ?", normalizeEmail(req.Email)).First(&user).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("login: db error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		crypto.CheckPasswordHash(req.Password, h.dummyHash) // equalize timing
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}

	if !crypto.CheckPasswordHash(req.Password, user.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}

	token, err := middleware.GenerateToken(user.ID, user.Role, h.Cfg.JWTSecret, h.Cfg.JWTIssuer, h.Cfg.JWTTTL)
	if err != nil {
		log.Printf("login: token signing error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":      token,
		"token_type": "Bearer",
		"expires_in": int(h.Cfg.JWTTTL.Seconds()),
		"user":       gin.H{"id": user.ID, "email": user.Email, "role": user.Role},
	})
}

func normalizeEmail(e string) string {
	return strings.ToLower(strings.TrimSpace(e))
}

// isUniqueViolation detects PostgreSQL error 23505 (unique_violation) as a
// fallback when GORM's TranslateError is not enabled.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "23505")
}
