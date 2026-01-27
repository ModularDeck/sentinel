package main

import (
	"log"
	"net/http"

	"sentinel/internal/auth"
	"sentinel/internal/db"
	"sentinel/internal/handlers"

	"github.com/gorilla/mux"
)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	// Initialize the database
	log.Println("Initializing database connection...")
	db.InitDB()
	defer db.DB.Close()

	// Create a new router
	r := mux.NewRouter()

	// Apply rate limiting middleware globally
	r.Use(auth.RateLimitMiddleware)

	// Health check endpoint
	r.HandleFunc("/health", healthHandler).Methods("GET")

	// Public routes (no authentication required)
	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		handlers.LoginHandler(w, r, db.DB)
	}).Methods("POST")
	r.HandleFunc("/register", handlers.RegisterUser).Methods("POST")
	r.HandleFunc("/logout", handlers.LogoutHandler).Methods("POST")

	// Password reset routes
	r.HandleFunc("/request-password-reset", func(w http.ResponseWriter, r *http.Request) {
		handlers.ForgotPasswordHandler(w, r, db.DB)
	}).Methods("POST")
	r.HandleFunc("/reset-password", func(w http.ResponseWriter, r *http.Request) {
		handlers.ResetPasswordHandler(w, r, db.DB)
	}).Methods("POST")

	// Email verification webhook
	r.HandleFunc("/webhooks/verify-email", func(w http.ResponseWriter, r *http.Request) {
		handlers.VerifyEmailHandler(w, r, db.DB)
	}).Methods("GET")
	r.HandleFunc("/webhooks/resend-email", handlers.ResendVerificationHandler).Methods("POST")

	// Secure routes with JWT middleware
	secure := r.PathPrefix("/api").Subrouter()
	secure.Use(func(next http.Handler) http.Handler {
		return auth.AuthMiddleware(next, db.DB)
	})

	// User routes
	secure.HandleFunc("/user/{id}", handlers.GetUserDetails).Methods("GET")
	secure.HandleFunc("/userinfo", handlers.GetUserDetails).Methods("GET")
	secure.HandleFunc("/user", handlers.UpdateUserDetailsHandler).Methods("PUT")
	secure.HandleFunc("/user/tenant/{tenant_id}", handlers.GetUsersByTenant).Methods("GET")
	secure.HandleFunc("/user/{id}", handlers.DeleteUserHandler).Methods("DELETE")
	secure.HandleFunc("/user", handlers.RegisterUserAgainstTenantId).Methods("POST")

	// Team routes
	secure.HandleFunc("/team", handlers.GetTeamsByTenantHandler).Methods("GET")
	secure.HandleFunc("/team", handlers.CreateOrUpdateTeamHandler).Methods("POST", "PUT")
	secure.HandleFunc("/team/{id}", handlers.DeleteTeamHandler).Methods("DELETE")

	// Module routes
	secure.HandleFunc("/modules", handlers.GetModulesHandler).Methods("GET")

	r.PathPrefix("/api").Handler(secure)

	// Log all registered routes
	log.Println("Registered routes:")
	r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		pathTemplate, _ := route.GetPathTemplate()
		methods, _ := route.GetMethods()
		if pathTemplate != "" {
			log.Printf("  %s %v\n", pathTemplate, methods)
		}
		return nil
	})

	// Start server with CORS middleware
	log.Println("Sentinel starting on :8080")
	handler := auth.EnableCORS(r)
	log.Fatal(http.ListenAndServe(":8080", handler))
}
