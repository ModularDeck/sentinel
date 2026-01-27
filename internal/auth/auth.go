package auth

import (
	"errors"
	"log"
	"os"
	"sentinel/internal/db"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

// Claims struct to hold JWT claims
type Claims struct {
	Email    string `json:"email"`
	TenantID int    `json:"tenant_id"` // Add Tenant ID to support multi-tenancy
	Role     string `json:"role"`
	jwt.StandardClaims
}

// getJWTSecret retrieves the JWT secret from environment variables
func getJWTSecret() string {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Println("WARNING: JWT_SECRET not set, using default (not recommended for production)")
		secret = "change-me-in-production-use-strong-secret"
	}
	return secret
}

// GenerateJWT creates a JWT for authenticated users
func GenerateJWT(email string, tenantID int, role string) (string, error) {
	now := time.Now()
	expirationTime := now.Add(24 * time.Hour)
	claims := &Claims{
		Email:    email,
		TenantID: tenantID,
		Role:     role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  now.Unix(),
			Id:        uuid.New().String(), // Unique token ID for revocation tracking
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(getJWTSecret()))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// Patch point for blacklist check
var isTokenBlacklisted = func(token string) (bool, error) {
	var exists bool
	err := db.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM token_blacklist WHERE token=$1)", token).Scan(&exists)
	return exists, err
}

// Patch point for ValidateToken to allow mocking in tests
var ValidateToken = validateToken

func validateToken(tokenStr string) (*Claims, error) {
	jwtSecret := getJWTSecret()
	if jwtSecret == "" {
		log.Println("JWT secret not configured")
		return nil, errors.New("JWT secret not found")
	}

	claims := &Claims{}

	// Parse the token with claims
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})

	if err != nil {
		log.Printf("Error parsing token: %v\n", err)
		// Handle specific JWT validation errors
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, errors.New("token is expired")
			}
			if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
				return nil, errors.New("invalid token signature")
			}
		}
		return nil, errors.New("error validating token")
	}

	// Validate required claims
	if claims.IssuedAt == 0 {
		log.Println("Missing issued_at (iat) in token")
		return nil, errors.New("token missing issued time")
	}

	if claims.Id == "" {
		log.Println("Missing JWT ID (jti) in token")
	}

	// Check if the token is blacklisted
	exists, err := isTokenBlacklisted(tokenStr)
	if err != nil {
		log.Println("Token blacklist check error:", err)
		return nil, errors.New("token validation failed")
	}
	if exists {
		log.Println("Token is blacklisted")
		return nil, errors.New("token is revoked")
	}

	if !token.Valid {
		log.Println("Token is not valid")
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
