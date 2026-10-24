package middleware

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"health-metrics-vault/models"
)

// Context keys under which the authenticated identity is stored.
const (
	CtxUserID = "user_id"
	CtxRole   = "role"
)

// Claims is the JWT payload issued by the Mini-IAM.
type Claims struct {
	UserID uint        `json:"user_id"`
	Role   models.Role `json:"role"`
	jwt.RegisteredClaims
}

// GenerateToken issues a short-lived HS256 JWT for the given user.
//
// SECURITY: tokens carry an expiry (exp), issued-at (iat), not-before (nbf) and
// issuer (iss). Short TTLs limit the damage window of a stolen token.
func GenerateToken(userID uint, role models.Role, secret []byte, issuer string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

// AuthMiddleware validates the "Authorization: Bearer <token>" header and puts
// user_id and role into the Gin context for downstream handlers.
//
// SECURITY:
//   - WithValidMethods([HS256]) blocks the classic "alg: none" and
//     algorithm-confusion (RS256 -> HS256) attacks.
//   - Expiry, issuer and nbf are verified; expired/forged tokens => 401.
//   - The identity used for authorization is taken ONLY from the verified token,
//     never from request bodies/params supplied by the client.
func AuthMiddleware(secret []byte, issuer string) gin.HandlerFunc {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)

	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		tokenStr, ok := strings.CutPrefix(header, "Bearer ")
		if !ok || tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or malformed Authorization header"})
			return
		}

		claims := &Claims{}
		token, err := parser.ParseWithClaims(tokenStr, claims, func(_ *jwt.Token) (any, error) {
			return secret, nil
		})
		if err != nil || !token.Valid {
			msg := "invalid token"
			if errors.Is(err, jwt.ErrTokenExpired) {
				msg = "token expired"
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": msg})
			return
		}

		// Defense in depth: reject tokens with an unknown role or empty subject.
		if claims.UserID == 0 || !claims.Role.Valid() {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
			return
		}

		c.Set(CtxUserID, claims.UserID)
		c.Set(CtxRole, claims.Role)
		c.Next()
	}
}

// RequireRole is the RBAC gate: only the listed roles may pass.
// Must be mounted AFTER AuthMiddleware.
func RequireRole(roles ...models.Role) gin.HandlerFunc {
	return func(c *gin.Context) {
		role := GetRole(c)
		for _, r := range roles {
			if role == r {
				c.Next()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient role"})
	}
}

// GetUserID returns the authenticated user's ID (0 if absent).
func GetUserID(c *gin.Context) uint {
	v, _ := c.Get(CtxUserID)
	id, _ := v.(uint)
	return id
}

// GetRole returns the authenticated user's role ("" if absent).
func GetRole(c *gin.Context) models.Role {
	v, _ := c.Get(CtxRole)
	r, _ := v.(models.Role)
	return r
}
