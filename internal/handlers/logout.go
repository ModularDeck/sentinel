package handlers

import (
	"log"
	"net/http"
	"sentinel/internal/auth"
	"sentinel/internal/db"
	"strings"
)

// LogoutHandler handles user logout, blacklists the token, and cleans up active sessions
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Get the JWT token from the Authorization header
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		http.Error(w, "Authorization token not found", http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate token to get claims
	claims, err := auth.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	email := claims.Email
	tenantID := claims.TenantID

	// Add token to blacklist
	_, err = db.DB.Exec("INSERT INTO token_blacklist (token) VALUES ($1) ON CONFLICT DO NOTHING", token)
	if err != nil {
		log.Println("Error inserting into token_blacklist:", err)
		http.Error(w, "Error logging out", http.StatusInternalServerError)
		return
	}

	// Remove from active_sessions
	_, err = db.DB.Exec("DELETE FROM active_sessions WHERE email=$1 AND tenant_id=$2", email, tenantID)
	if err != nil {
		log.Println("Error removing active session:", err)
		// Don't fail the logout if session cleanup fails
	}

	// Clear the token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Logged out successfully"}`))
}
