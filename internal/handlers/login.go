// internal/handlers/login.go

package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sentinel/internal/auth"
	"sentinel/internal/db"
	"sentinel/internal/models"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// LoginHandler verifies the user's credentials and returns a JWT with tenant support.
// It logs login attempts for audit purposes and manages active sessions.
func LoginHandler(w http.ResponseWriter, r *http.Request, dbInstance *sql.DB) {
	var dbUser models.User
	var loginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	loginRequest.Email = strings.TrimSpace(strings.ToLower(loginRequest.Email))

	// Extract client IP for audit logging
	var ip string
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = strings.Split(forwarded, ",")[0]
	} else {
		ip, _, _ = strings.Cut(r.RemoteAddr, ":")
	}

	// Fetch user by email
	err = dbInstance.QueryRow(`
		SELECT id, name, password, tenant_id, role
		FROM users
		WHERE email = $1
	`, loginRequest.Email).
		Scan(&dbUser.ID, &dbUser.Name, &dbUser.Password, &dbUser.TenantID, &dbUser.Role)

	if err != nil {
		// Log failed login attempt
		_, _ = dbInstance.Exec(`
			INSERT INTO login_audit_logs (email, tenant_id, ip_address, login_status)
			VALUES ($1, NULL, $2, 'FAILED')
		`, loginRequest.Email, ip)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Validate password
	if err := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(loginRequest.Password)); err != nil {
		_, _ = dbInstance.Exec(`
			INSERT INTO login_audit_logs (email, tenant_id, ip_address, login_status)
			VALUES ($1, $2, $3, 'FAILED')
		`, loginRequest.Email, dbUser.TenantID, ip)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Log successful login
	_, _ = dbInstance.Exec(`
		INSERT INTO login_audit_logs (email, tenant_id, ip_address, login_status)
		VALUES ($1, $2, $3, 'SUCCESS')
	`, loginRequest.Email, dbUser.TenantID, ip)

	// Generate token
	tokenString, err := auth.GenerateJWT(loginRequest.Email, dbUser.TenantID, dbUser.Role)
	if err != nil {
		log.Println("Error generating JWT token:", err)
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}

	// Manage single-session: blacklist previous token if exists
	var oldToken string
	_ = dbInstance.QueryRow("SELECT token FROM active_sessions WHERE email=$1 AND tenant_id=$2", loginRequest.Email, dbUser.TenantID).
		Scan(&oldToken)
	if oldToken != "" {
		_, _ = dbInstance.Exec("INSERT INTO token_blacklist (token) VALUES ($1) ON CONFLICT DO NOTHING", oldToken)
	}

	// Save current session
	_, err = dbInstance.Exec(`
		INSERT INTO active_sessions (email, tenant_id, token, last_ip, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (email, tenant_id)
		DO UPDATE SET token = $3, last_ip = $4, updated_at = NOW()
	`, loginRequest.Email, dbUser.TenantID, tokenString, ip)

	if err != nil {
		log.Println("Error saving active session:", err)
		http.Error(w, "Could not save session", http.StatusInternalServerError)
		return
	}

	// Set cookie
	expirationTime := time.Now().Add(24 * time.Hour)
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Expires:  expirationTime,
		HttpOnly: true,
		Path:     "/",
	})

	// Return token in response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// ForgotPasswordHandler initiates password reset by sending a reset token
func ForgotPasswordHandler(w http.ResponseWriter, r *http.Request, dbInstance *sql.DB) {
	var req struct {
		Email string `json:"email"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || strings.TrimSpace(req.Email) == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	var tenantID int
	err = dbInstance.QueryRow(`SELECT tenant_id FROM users WHERE email=$1`, email).Scan(&tenantID)
	if err != nil {
		// Don't reveal if email exists or not for security
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "If the email exists, a reset link will be sent."})
		return
	}

	// Generate secure token
	resetToken := GenerateSecureToken(32)
	expiry := time.Now().Add(30 * time.Minute)

	_, err = dbInstance.Exec(`
		UPDATE users
		SET reset_token = $1, reset_token_expiry = $2
		WHERE email = $3
	`, resetToken, expiry, email)

	if err != nil {
		log.Println("DB error:", err)
		http.Error(w, "Could not process request", http.StatusInternalServerError)
		return
	}

	// Log the reset token - in production, send this via email
	// You can integrate your email service here
	log.Printf("Password reset token for %s: %s (expires: %v)", email, resetToken, expiry)

	// If email service is configured via EMAIL_SERVICE_URL, you could call it here
	// For now, just log the token

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "If the email exists, a reset link will be sent."})
}

// ResetPasswordHandler handles password reset with a valid token
func ResetPasswordHandler(w http.ResponseWriter, r *http.Request, dbInstance *sql.DB) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.Token == "" || len(req.NewPassword) < 8 {
		http.Error(w, "Invalid input. Password must be at least 8 characters.", http.StatusBadRequest)
		return
	}

	var userID int
	var expiry time.Time

	err = dbInstance.QueryRow(`
		SELECT id, reset_token_expiry
		FROM users
		WHERE reset_token = $1
	`, req.Token).Scan(&userID, &expiry)

	if err != nil || time.Now().After(expiry) {
		http.Error(w, "Token is invalid or expired", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	_, err = dbInstance.Exec(`
		UPDATE users
		SET password = $1, reset_token = NULL, reset_token_expiry = NULL
		WHERE id = $2
	`, hashedPassword, userID)

	if err != nil {
		http.Error(w, "Could not reset password", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Password reset successful"})
}

// GenerateSecureToken generates a cryptographically secure random token
func GenerateSecureToken(n int) string {
	bytes := make([]byte, n)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// VerifyEmailHandler verifies a user's email address using a confirmation token
func VerifyEmailHandler(w http.ResponseWriter, r *http.Request, dbInstance *sql.DB) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	res, err := db.DB.Exec(`UPDATE users SET email_confirmed = TRUE, confirmation_token = NULL WHERE confirmation_token = $1`, token)
	if err != nil {
		http.Error(w, "Verification failed", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	// Redirect to configured URL or return success
	redirectURL := os.Getenv("EMAIL_VERIFIED_REDIRECT_URL")
	if redirectURL != "" {
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Email verified successfully"})
}

// ResendVerificationHandler resends the email verification link
func ResendVerificationHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.Email == "" {
		http.Error(w, "Invalid email", http.StatusBadRequest)
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	var userID, tenantID int
	var userName string
	var confirmed bool

	err = db.DB.QueryRow(`
		SELECT u.id, u.name, COALESCE(u.email_confirmed, false), u.tenant_id
		FROM users u
		WHERE u.email = $1
	`, req.Email).Scan(&userID, &userName, &confirmed, &tenantID)

	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if confirmed {
		http.Error(w, "Email already verified", http.StatusBadRequest)
		return
	}

	token := uuid.New().String()
	_, err = db.DB.Exec(`UPDATE users SET confirmation_token = $1 WHERE id = $2`, token, userID)
	if err != nil {
		http.Error(w, "Failed to generate confirmation token", http.StatusInternalServerError)
		return
	}

	// Build verification link
	baseURL := os.Getenv("APP_BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	link := fmt.Sprintf("%s/webhooks/verify-email?token=%s", baseURL, token)

	// Log the verification link - in production, send this via email
	log.Printf("Email verification link for %s: %s", req.Email, link)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Verification email sent successfully",
	})
}
