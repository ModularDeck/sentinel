package auth

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

const (
	ErrTooManyRequests = "Too Many Requests"
)

type CtxKey string

const (
	EmailKey    CtxKey = "email"
	TenantIDKey CtxKey = "tenant_id"
	RoleKey     CtxKey = "role"
)

// AuthMiddleware checks for the JWT token and validates it
func AuthMiddleware(next http.Handler, dbInstance *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Extract token
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := ValidateToken(tokenStr)
		if err != nil {
			log.Println("JWT validation failed:", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Check if token is blacklisted
		var blacklisted bool
		err = dbInstance.QueryRow("SELECT EXISTS(SELECT 1 FROM token_blacklist WHERE token=$1)", tokenStr).Scan(&blacklisted)
		if err != nil || blacklisted {
			log.Println("Token blacklisted or error:", err)
			http.Error(w, "Token is invalid or blacklisted", http.StatusUnauthorized)
			return
		}

		// Check if user still exists
		var userExists bool
		err = dbInstance.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email=$1 AND tenant_id=$2)", claims.Email, claims.TenantID).Scan(&userExists)
		if err != nil || !userExists {
			log.Println("User not found or error:", err)
			http.Error(w, "User does not exist", http.StatusUnauthorized)
			return
		}

		// Check email verification if enabled (set REQUIRE_EMAIL_VERIFICATION=true to enable)
		if os.Getenv("REQUIRE_EMAIL_VERIFICATION") == "true" {
			var confirmed bool
			err = dbInstance.QueryRow("SELECT COALESCE(email_confirmed, false) FROM users WHERE email=$1 AND tenant_id=$2", claims.Email, claims.TenantID).Scan(&confirmed)
			if err != nil || !confirmed {
				log.Println("Email not verified")
				http.Error(w, "Please verify your email before accessing the application", http.StatusForbidden)
				return
			}
		}

		// Enforce single-session login if enabled (set SINGLE_SESSION=true to enable)
		if os.Getenv("SINGLE_SESSION") == "true" {
			var dbToken, dbIP string
			err = dbInstance.QueryRow("SELECT token, last_ip FROM active_sessions WHERE email=$1 AND tenant_id=$2", claims.Email, claims.TenantID).Scan(&dbToken, &dbIP)
			if err != nil {
				log.Println("Active session not found:", err)
				http.Error(w, "Session not found or user logged in elsewhere", http.StatusUnauthorized)
				return
			}

			if dbToken != tokenStr {
				// Blacklist the old token
				_, _ = dbInstance.Exec("INSERT INTO token_blacklist (token) VALUES ($1) ON CONFLICT DO NOTHING", dbToken)

				// Update active session with new token
				var ip string
				if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
					ip = strings.Split(forwarded, ",")[0]
				} else {
					ip, _, _ = strings.Cut(r.RemoteAddr, ":")
				}
				_, _ = dbInstance.Exec(`
					UPDATE active_sessions SET token=$1, last_ip=$2, updated_at=NOW()
					WHERE email=$3 AND tenant_id=$4
				`, tokenStr, ip, claims.Email, claims.TenantID)

				log.Println("Token mismatch, previous session logged out")
			}
		}

		// Attach claims to context
		ctx := context.WithValue(r.Context(), EmailKey, claims.Email)
		ctx = context.WithValue(ctx, TenantIDKey, claims.TenantID)
		ctx = context.WithValue(ctx, RoleKey, claims.Role)
		r = r.WithContext(ctx)

		// Continue to handler
		next.ServeHTTP(w, r)
	})
}

// GetTenantID fetches the tenant_id from the context
func GetTenantID(ctx context.Context) (int, error) {
	tenantIDValue := ctx.Value(TenantIDKey)
	tenantID, ok := tenantIDValue.(int)

	if !ok {
		log.Println("Error: tenant_id not found in context or invalid type")
		return 0, errors.New("tenant_id not found in context or invalid type")
	}
	return tenantID, nil
}

// GetRole retrieves the user's role from the context
func GetRole(ctx context.Context) (string, error) {
	role := ctx.Value(RoleKey)
	roleValue, ok := role.(string)
	if !ok {
		log.Println("Error: role not found in context or invalid type")
		return "", errors.New("role not found in context or invalid type")
	}
	return roleValue, nil
}

// GetEmail fetches the email from the context
func GetEmail(ctx context.Context) (string, error) {
	emailValue := ctx.Value(EmailKey)
	email, ok := emailValue.(string)

	if !ok {
		log.Println("Error: email not found in context or invalid type")
		return "", errors.New("email not found in context or invalid type")
	}
	return email, nil
}

// User-specific rate limiter map
var (
	userLimiters = make(map[string]*rate.Limiter)
	mu           sync.Mutex
)

func getUserLimiter(user string) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	limiter, exists := userLimiters[user]
	if !exists {
		// Fetch rate limit configuration from environment variables
		rateLimit := 100
		burstLimit := 300

		if rl, ok := os.LookupEnv("RATE_LIMIT"); ok {
			if parsedRate, err := strconv.Atoi(rl); err == nil {
				rateLimit = parsedRate
			}
		}
		if bl, ok := os.LookupEnv("BURST_LIMIT"); ok {
			if parsedBurst, err := strconv.Atoi(bl); err == nil {
				burstLimit = parsedBurst
			}
		}

		limiter = rate.NewLimiter(rate.Limit(rateLimit), burstLimit)
		userLimiters[user] = limiter
	}
	return limiter
}

// RateLimitMiddleware applies rate limiting per user
func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting for public endpoints
		publicPaths := []string{"/health", "/register", "/login", "/logout", "/request-password-reset", "/reset-password"}
		for _, path := range publicPaths {
			if r.URL.Path == path {
				next.ServeHTTP(w, r)
				return
			}
		}
		// Skip webhooks
		if strings.HasPrefix(r.URL.Path, "/webhooks/") {
			next.ServeHTTP(w, r)
			return
		}

		// Extract user identifier from the Authorization header
		user := r.Header.Get("Authorization")
		if user == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		limiter := getUserLimiter(user)
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// getAllowedOrigins returns the list of allowed CORS origins from environment
func getAllowedOrigins() map[string]bool {
	origins := map[string]bool{
		"http://localhost:5173": true, // Default for local development
		"http://localhost:3000": true,
	}

	// Add custom origins from environment variable (comma-separated)
	if customOrigins := os.Getenv("CORS_ALLOWED_ORIGINS"); customOrigins != "" {
		for _, origin := range strings.Split(customOrigins, ",") {
			origins[strings.TrimSpace(origin)] = true
		}
	}

	return origins
}

// EnableCORS adds CORS headers to responses
func EnableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowedOrigins := getAllowedOrigins()

		if allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
