package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CORS allows the React frontend (running on another local port) to call the API.
//
// SECURITY:
//   - Strict allow-list: only origins from CORS_ALLOWED_ORIGINS get the
//     Access-Control-Allow-Origin header. Wildcard "*" is rejected at config load.
//   - The request origin is reflected ONLY if it is in the allow-list, and
//     "Vary: Origin" prevents caches from serving one origin's response to another.
//   - Credentials (cookies) are not enabled: auth uses the Authorization header,
//     which also makes the API immune to classic CSRF.
func CORS(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = struct{}{}
	}

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		_, ok := allowed[origin]

		if origin != "" {
			c.Header("Vary", "Origin")
		}
		if ok {
			h := c.Writer.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			h.Set("Access-Control-Max-Age", "600")
		}

		// Short-circuit preflight requests.
		if c.Request.Method == http.MethodOptions {
			if ok {
				c.AbortWithStatus(http.StatusNoContent)
			} else {
				c.AbortWithStatus(http.StatusForbidden)
			}
			return
		}
		c.Next()
	}
}
