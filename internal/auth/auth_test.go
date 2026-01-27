package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
)

func TestGenerateJWT(t *testing.T) {
	email := "test@example.com"
	tenantID := 1
	role := "admin"

	token, err := GenerateJWT(email, tenantID, role)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if token == "" {
		t.Error("Expected a token string, got empty string")
	}
}

func TestValidateToken_Valid(t *testing.T) {
	email := "test@example.com"
	tenantID := 1
	role := "admin"

	token, err := GenerateJWT(email, tenantID, role)
	if err != nil {
		t.Fatalf("Error generating token: %v", err)
	}

	// Mock blacklist check to always return false (not blacklisted)
	origBlacklist := isTokenBlacklisted
	isTokenBlacklisted = func(token string) (bool, error) { return false, nil }
	defer func() { isTokenBlacklisted = origBlacklist }()

	claims, err := ValidateToken(token)
	if err != nil {
		t.Fatalf("Expected valid token, got error: %v", err)
	}
	if claims.Email != email || claims.TenantID != tenantID || claims.Role != role {
		t.Error("Claims do not match input values")
	}
}

func TestValidateToken_Blacklisted(t *testing.T) {
	email := "test@example.com"
	tenantID := 1
	role := "admin"

	token, err := GenerateJWT(email, tenantID, role)
	if err != nil {
		t.Fatalf("Error generating token: %v", err)
	}

	// Mock blacklist check to simulate a blacklisted token
	origBlacklist := isTokenBlacklisted
	isTokenBlacklisted = func(token string) (bool, error) { return true, nil }
	defer func() { isTokenBlacklisted = origBlacklist }()

	_, err = ValidateToken(token)
	if err == nil || err.Error() != "token is expired" {
		t.Errorf("Expected 'token is expired' error, got: %v", err)
	}
}

func TestValidateToken_InvalidSignature(t *testing.T) {
	// Create a token with a different secret
	claims := &Claims{
		Email:    "test@example.com",
		TenantID: 1,
		Role:     "admin",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	badKey := []byte("wrongsecret")
	tokenString, _ := token.SignedString(badKey)

	// Mock blacklist check to always return false (not blacklisted)
	origBlacklist := isTokenBlacklisted
	isTokenBlacklisted = func(token string) (bool, error) { return false, nil }
	defer func() { isTokenBlacklisted = origBlacklist }()

	_, err := ValidateToken(tokenString)
	if err == nil || err.Error() != "invalid token signature" {
		t.Errorf("Expected 'invalid token signature' error, got: %v", err)
	}
}

func TestValidateToken_Expired(t *testing.T) {
	claims := &Claims{
		Email:    "test@example.com",
		TenantID: 1,
		Role:     "admin",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtKey := "secret"
	tokenString, _ := token.SignedString([]byte(jwtKey))

	// Mock blacklist check to always return false (not blacklisted)
	origBlacklist := isTokenBlacklisted
	isTokenBlacklisted = func(token string) (bool, error) { return false, nil }
	defer func() { isTokenBlacklisted = origBlacklist }()

	_, err := ValidateToken(tokenString)
	if err == nil || err.Error() != "token is expired" {
		t.Errorf("Expected 'token is expired' error, got: %v", err)
	}
}
