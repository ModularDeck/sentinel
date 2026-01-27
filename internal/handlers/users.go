package handlers

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"
	"sentinel/internal/auth"
	"sentinel/internal/db"
	"sentinel/internal/models"
	"strings"

	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// validateEmail checks if the email format is valid
func validateEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// validatePassword checks if the password meets complexity requirements
func validatePassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`\d`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[\W_]`).MatchString(password)
	return hasLower && hasUpper && hasDigit && hasSpecial
}

// RegisterUserAgainstTenantId registers a new user under an existing tenant (admin only)
func RegisterUserAgainstTenantId(w http.ResponseWriter, r *http.Request) {
	var req models.Req_User_Login
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.Email == "" || req.Password == "" {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))

	if !validateEmail(req.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	if !validatePassword(req.Password) {
		http.Error(w, "Password must be at least 8 characters with uppercase, lowercase, number, and special character", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	tenantID, err := auth.GetTenantID(ctx)
	if err != nil || tenantID == 0 {
		log.Println("Missing tenant ID from token")
		http.Error(w, "Missing tenant ID from token", http.StatusBadRequest)
		return
	}

	if req.UserTeamRole == "" {
		req.UserTeamRole = "member"
	}

	tx, err := db.DB.Begin()
	if err != nil {
		log.Println("Failed to start transaction:", err)
		http.Error(w, "Failed to start transaction", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	var teamID int
	err = tx.QueryRow(`
		INSERT INTO teams (tenant_id, name, description, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, name) 
		DO UPDATE SET description = EXCLUDED.description, updated_at = EXCLUDED.updated_at
		RETURNING id
	`, tenantID, req.TeamName, req.TeamDesc, time.Now(), time.Now()).Scan(&teamID)
	if err != nil {
		http.Error(w, "Error creating or updating team", http.StatusInternalServerError)
		return
	}

	if req.UserRole == "" {
		req.UserRole = "member"
	}

	var userID int
	err = tx.QueryRow(`
		INSERT INTO users (tenant_id, name, email, password, role, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (email) DO UPDATE SET password = EXCLUDED.password, updated_at = EXCLUDED.updated_at
		RETURNING id
	`, tenantID, req.UserName, req.Email, string(hashedPassword), req.UserRole, time.Now(), time.Now()).Scan(&userID)
	if err != nil {
		http.Error(w, "Error creating or updating user", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec(`
		INSERT INTO user_teams (user_id, team_id, role, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, team_id) DO UPDATE SET role = EXCLUDED.role, updated_at = EXCLUDED.updated_at
	`, userID, teamID, req.UserTeamRole, time.Now(), time.Now())
	if err != nil {
		http.Error(w, "Error adding user to team", http.StatusInternalServerError)
		return
	}

	err = tx.Commit()
	if err != nil {
		http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message":   "User created successfully with tenant and team",
		"user_id":   strconv.Itoa(userID),
		"tenant_id": strconv.Itoa(tenantID),
		"team_id":   strconv.Itoa(teamID),
	})
}

// RegisterUser handles new user registration with tenant and team creation
func RegisterUser(w http.ResponseWriter, r *http.Request) {
	var req models.Req_User_Login
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || req.Email == "" || req.Password == "" || req.TenantName == "" {
		http.Error(w, "Invalid input: email, password, and tenant_name are required", http.StatusBadRequest)
		return
	}

	// Validate and normalize email
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if !validateEmail(req.Email) {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	// Validate password complexity
	if !validatePassword(req.Password) {
		http.Error(w, "Password must be at least 8 characters with uppercase, lowercase, number, and special character", http.StatusBadRequest)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	// Set default tenant name if not provided
	if req.TenantName == "" {
		req.TenantName = req.UserName + "'s Organization"
	}

	// Start transaction
	tx, err := db.DB.Begin()
	if err != nil {
		log.Println("Failed to start transaction:", err)
		http.Error(w, "Failed to start transaction", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Step 1: Create tenant (fail if exists)
	var tenantID int
	err = tx.QueryRow(`
		INSERT INTO tenants (name, description, created_at, updated_at) 
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (name) DO NOTHING
		RETURNING id
	`, req.TenantName, req.TenantDesc, time.Now(), time.Now()).Scan(&tenantID)
	if err == sql.ErrNoRows {
		log.Printf("Tenant %s already exists", req.TenantName)
		http.Error(w, "Tenant already exists, please use a different name", http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(w, "Error creating tenant", http.StatusInternalServerError)
		return
	}

	// Step 2: Check if user already exists
	var existingUserID int
	err = tx.QueryRow(`SELECT id FROM users WHERE email = $1`, req.Email).Scan(&existingUserID)
	if err != sql.ErrNoRows {
		if err == nil {
			http.Error(w, "User with this email already exists", http.StatusConflict)
			return
		}
		http.Error(w, "Error checking existing user", http.StatusInternalServerError)
		return
	}

	// Step 3: Create user
	if req.UserRole == "" {
		req.UserRole = "admin" // First user is admin by default
	}

	var userID int
	err = tx.QueryRow(`
		INSERT INTO users (tenant_id, name, email, password, role, created_at, updated_at, mobile) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, tenantID, req.UserName, req.Email, string(hashedPassword), req.UserRole, time.Now(), time.Now(), req.Mobile).Scan(&userID)
	if err != nil {
		log.Println("Error creating user:", err)
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	// Step 4: Create default team
	if req.TeamName == "" {
		req.TeamName = req.TenantName + " Default Team"
	}
	if req.TeamDesc == "" {
		req.TeamDesc = "Default team for " + req.TenantName
	}

	var teamID int
	err = tx.QueryRow(`
		INSERT INTO teams (tenant_id, name, description, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, name) 
		DO UPDATE SET description = EXCLUDED.description, updated_at = EXCLUDED.updated_at
		RETURNING id
	`, tenantID, req.TeamName, req.TeamDesc, time.Now(), time.Now()).Scan(&teamID)
	if err != nil {
		http.Error(w, "Error creating team", http.StatusInternalServerError)
		return
	}

	// Step 5: Add user to team
	if req.UserTeamRole == "" {
		req.UserTeamRole = "admin"
	}

	_, err = tx.Exec(`
		INSERT INTO user_teams (user_id, team_id, role, created_at, updated_at) 
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (user_id, team_id) DO UPDATE SET role = EXCLUDED.role, updated_at = EXCLUDED.updated_at
	`, userID, teamID, req.UserTeamRole, time.Now(), time.Now())
	if err != nil {
		http.Error(w, "Error adding user to team", http.StatusInternalServerError)
		return
	}

	// Step 6: Generate email confirmation token if email verification is enabled
	var confirmationToken string
	if os.Getenv("REQUIRE_EMAIL_VERIFICATION") == "true" {
		confirmationToken = uuid.New().String()
		_, err = tx.Exec(`UPDATE users SET confirmation_token = $1 WHERE id = $2`, confirmationToken, userID)
		if err != nil {
			http.Error(w, "Failed to set confirmation token", http.StatusInternalServerError)
			return
		}
	}

	// Commit the transaction
	err = tx.Commit()
	if err != nil {
		http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
		return
	}

	// Log confirmation URL if email verification is enabled
	if confirmationToken != "" {
		baseURL := os.Getenv("APP_BASE_URL")
		if baseURL == "" {
			baseURL = "http://localhost:8080"
		}
		confirmURL := fmt.Sprintf("%s/webhooks/verify-email?token=%s", baseURL, confirmationToken)
		log.Printf("Email confirmation URL for %s: %s", req.Email, confirmURL)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message":   "User created successfully with tenant and team",
		"user_id":   strconv.Itoa(userID),
		"tenant_id": strconv.Itoa(tenantID),
		"team_id":   strconv.Itoa(teamID),
	})
}

// GetUserDetails fetches the user along with tenant and team information
func GetUserDetails(w http.ResponseWriter, r *http.Request) {
	// userIDStr := r.URL.Query().Get("id") // expecting ?id= in the URL query
	// userID, err := strconv.Atoi(userIDStr)

	// Fetch user, tenant, and team details
	var user models.User
	var tenant models.Tenant
	var team models.Team
	var userID int
	var e, err error

	vars := mux.Vars(r)
	id := vars["id"]

	if id == "" {
		// Retrieve the user's email and tenant ID from the JWT token in the context
		ctx := r.Context()
		email, err := auth.GetEmail(ctx)
		if err != nil || email == "" {
			log.Println("Missing user ID and email from token")
			http.Error(w, "Missing user ID and email from token", http.StatusBadRequest)
			return
		}

		tenantID, err := auth.GetTenantID(ctx)
		if err != nil {
			log.Println("Missing tenant ID from token")
			http.Error(w, "Missing tenant ID from token", http.StatusBadRequest)
			return
		}

		// Fetch user ID using email and tenant ID
		err = db.DB.QueryRow(`
			SELECT id FROM users WHERE email = $1 AND tenant_id = $2
		`, email, tenantID).Scan(&userID)

		if err != nil {
			log.Println("Error fetching user ID:", err)
			http.Error(w, "Error fetching user ID", http.StatusInternalServerError)
			return
		}
	} else {
		// Convert userID from string to int
		userID, e = strconv.Atoi(id)
		if e != nil {
			log.Println("Invalid user ID:", e)
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}
	}
	// Convert userID from string to int

	ctxTenantID, _ := auth.GetTenantID(r.Context())

	var (
		userIDVal     sql.NullInt64
		userNameVal   sql.NullString
		userEmailVal  sql.NullString
		tenantIDVal   sql.NullInt64
		tenantNameVal sql.NullString
		teamIDVal     sql.NullInt64
		teamNameVal   sql.NullString
	)

	var userRoleVal sql.NullString

	err = db.DB.QueryRow(`
		SELECT u.id, u.name, u.email, t.id, t.name, tm.id, tm.name, u.role
		FROM users u
		JOIN tenants t ON u.tenant_id = t.id
		LEFT JOIN user_teams ut ON ut.user_id = u.id
		LEFT JOIN teams tm ON tm.id = ut.team_id
		WHERE u.id = $1 and u.tenant_id = $2`, userID, ctxTenantID).Scan(
		&userIDVal, &userNameVal, &userEmailVal,
		&tenantIDVal, &tenantNameVal,
		&teamIDVal, &teamNameVal, &userRoleVal,
	)

	if err != nil {
		http.Error(w, "Error fetching user details", http.StatusInternalServerError)
		return
	}

	if userIDVal.Valid {
		user.ID = int(userIDVal.Int64)
	}
	if userNameVal.Valid {
		user.Name = userNameVal.String
	}
	if userEmailVal.Valid {
		user.Email = userEmailVal.String
	}
	if tenantIDVal.Valid {
		tenant.ID = int(tenantIDVal.Int64)
	}
	if tenantNameVal.Valid {
		tenant.Name = tenantNameVal.String
	}
	if teamIDVal.Valid {
		team.ID = int(teamIDVal.Int64)
	}
	if teamNameVal.Valid {
		team.Name = teamNameVal.String
	}
	if userRoleVal.Valid {
		user.Role = userRoleVal.String
	}

	response := map[string]interface{}{
		"user_id":     user.ID,
		"user_name":   user.Name,
		"user_email":  user.Email,
		"tenant_id":   tenant.ID,
		"tenant_name": tenant.Name,
		"team_id":     team.ID,
		"team_name":   team.Name,
		"role":        user.Role,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func UpdateUserDetailsHandler(w http.ResponseWriter, r *http.Request) {
	UpdateUserDetails(w, r, db.DB) // Pass the global db instance here
}

// UpdateUserDetails updates user, tenant, and team information
func UpdateUserDetails(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	var req struct {
		UserID     int    `json:"user_id"`
		Name       string `json:"name"`
		Email      string `json:"email"`
		Password   string `json:"password,omitempty"`
		TenantName string `json:"tenant_name"`
		TeamName   string `json:"team_name"`
		Role       string `json:"role,omitempty"` // Role can be "admin", "member", etc.
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Retrieve the user's email from the context
	ctx := r.Context()
	email, err := auth.GetEmail(ctx) // Assuming GetEmail returns email from context
	if err != nil || email == "" {
		http.Error(w, "Unauthorized User", http.StatusUnauthorized)
		return
	}

	// Check if the user trying to update is the owner of the UserID
	var currentUser models.User
	err = db.QueryRow("SELECT id, email, role FROM users WHERE id=$1", req.UserID).Scan(&currentUser.ID, &currentUser.Email, &currentUser.Role)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	role, _ := auth.GetRole(ctx)
	// Allow update only if the user is an admin or is updating their own details
	if role != "admin" {
		http.Error(w, "Unauthorized to update this user", http.StatusUnauthorized)
		return
	}

	// Hash the new password if provided
	var hashedPassword string
	if req.Password != "" {
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error creating password", http.StatusInternalServerError)
			return
		}
		hashedPassword = string(passwordHash)
	}

	if req.Password != "" && req.Email != "" {
		// Update user with password
		_, err = db.Exec(`UPDATE users SET name=$1, email=$2, password=$3 WHERE id=$4`,
			req.Name, req.Email, hashedPassword, req.UserID)
		if err != nil {
			http.Error(w, "Error inserting password", http.StatusInternalServerError)
			return
		}
	} else {

		if req.Name != "" {
			_, err = db.Exec(`UPDATE users SET name=$1 WHERE id=$2`,
				req.Name, req.UserID)
		}
	}
	if err != nil {
		http.Error(w, "Error updating user", http.StatusInternalServerError)
		return
	}

	// Update tenant information
	if req.TenantName != "" {
		_, err = db.Exec(`UPDATE tenants SET name=$1 WHERE id=(SELECT tenant_id FROM users WHERE id=$2)`, req.TenantName, req.UserID)
		if err != nil {
			http.Error(w, "Error updating tenant", http.StatusInternalServerError)
			return
		}
	}

	// Update or create a new team for the user
	if req.TeamName != "" {
		var teamID int
		tenantID := 0
		// Get tenant_id for the user
		err = db.QueryRow(`SELECT tenant_id FROM users WHERE id=$1`, req.UserID).Scan(&tenantID)
		if err != nil {
			http.Error(w, "Error fetching tenant for user", http.StatusInternalServerError)
			return
		}

		// Try to get the team ID, or insert if not exists
		err = db.QueryRow(`SELECT id FROM teams WHERE name=$1 AND tenant_id=$2`, req.TeamName, tenantID).Scan(&teamID)
		if err == sql.ErrNoRows {
			// Insert new team
			err = db.QueryRow(`
				INSERT INTO teams (tenant_id, name, description, created_at, updated_at)
				VALUES ($1, $2, $3, NOW(), NOW())
				RETURNING id
			`, tenantID, req.TeamName, "Team for "+req.TeamName).Scan(&teamID)
			if err != nil {
				http.Error(w, "Error creating team", http.StatusInternalServerError)
				return
			}

		} else if err != nil {
			http.Error(w, "Error fetching team", http.StatusInternalServerError)
			return
		} else {
			// Update existing team
			_, err = db.Exec(`UPDATE teams SET name=$1, updated_at=NOW() WHERE id=$2`, req.TeamName, teamID)
			if err != nil {
				http.Error(w, "Error updating team", http.StatusInternalServerError)
				return
			}
		}
		log.Printf("Team ID: %d, User ID: %d", teamID, req.UserID)

		res, err := db.Exec(`
				UPDATE user_teams SET role=COALESCE($1, role), updated_at=NOW(), team_id=$3
				WHERE user_id=$2
			`, req.Role, req.UserID, teamID)
		if err != nil {
			http.Error(w, "Error updating user team", http.StatusInternalServerError)
			return
		}
		rowsAffected, err := res.RowsAffected()
		if err != nil {
			http.Error(w, "Error checking update result", http.StatusInternalServerError)
			return
		}
		if rowsAffected == 0 {
			_, err = db.Exec(`
				INSERT INTO user_teams (user_id, team_id, role, created_at, updated_at)
				VALUES ($1, $2, $3, NOW(), NOW())
			`, req.UserID, teamID, req.Role)
			if err != nil {
				http.Error(w, "Error inserting user team", http.StatusInternalServerError)
				return
			}
		}
	}

	if req.Role != "" {
		// Update user role if provided
		_, err = db.Exec(`UPDATE users SET role=$1 WHERE id=$2`, req.Role, req.UserID)
		if err != nil {
			http.Error(w, "Error updating user role", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User details updated successfully"})
}

// GetUsersByTenant retrieves users by tenant ID along with tenant and team information
func GetUsersByTenant(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID, err := strconv.Atoi(vars["tenant_id"])
	if err != nil {
		http.Error(w, "Invalid tenant ID", http.StatusBadRequest)
		return
	}

	// Retrieve the user's email and tenant ID from the context
	ctx := r.Context()
	email, err := auth.GetEmail(ctx)
	if err != nil || email == "" {
		http.Error(w, "Unauthorized User", http.StatusUnauthorized)
		return
	}

	var currentUser models.User
	err = db.DB.QueryRow("SELECT id, email, role, tenant_id FROM users WHERE email=$1", email).Scan(&currentUser.ID, &currentUser.Email, &currentUser.Role, &currentUser.TenantID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	role, _ := auth.GetRole(ctx)

	// Check if the user is an admin and belongs to the same tenant
	if role != "admin" || currentUser.TenantID != tenantID {
		http.Error(w, "Unauthorized to access this tenant's users", http.StatusUnauthorized)
		return
	}

	users, err := GetUsersByTenantDB(tenantID)
	if err != nil {
		http.Error(w, "Failed to fetch users", http.StatusInternalServerError)
		return
	}

	// Fetch tenant information
	var tenant models.Tenant
	err = db.DB.QueryRow(`
		SELECT id, name, description 
		FROM tenants 
		WHERE id = $1
	`, tenantID).Scan(&tenant.ID, &tenant.Name, &tenant.Description)
	if err != nil {
		http.Error(w, "Failed to fetch tenant information", http.StatusInternalServerError)
		return
	}

	// Fetch team information for each user
	for i := range users {
		var team models.Team
		err = db.DB.QueryRow(`
			SELECT t.id, t.name, t.description 
			FROM teams t
			JOIN user_teams ut ON t.id = ut.team_id
			WHERE ut.user_id = $1
		`, users[i].ID).Scan(&team.ID, &team.Name, &team.Description)
		if err == nil {
			users[i].Team = team
		}
	}

	response := map[string]interface{}{
		"tenant": map[string]interface{}{
			"id":          tenant.ID,
			"name":        tenant.Name,
			"description": tenant.Description,
		},
		"users": users,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetUsersByTenantDB(tenantID int) ([]models.User, error) {
	var users []models.User
	rows, err := db.DB.Query(`
		SELECT id, name, email, role, tenant_id, created_at, updated_at
		FROM users
		WHERE tenant_id = $1
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Name, &user.Email, &user.Role, &user.TenantID, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	role, _ := auth.GetRole(ctx)
	if role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	userIDStr := vars["id"]
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	_, err = db.DB.Exec(`DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		http.Error(w, "Error deleting user", http.StatusInternalServerError)
		return
	}
	_, err = db.DB.Exec(`DELETE FROM user_teams WHERE user_id = $1`, userID)
	if err != nil {
		http.Error(w, "Error deleting user teams", http.StatusInternalServerError)
		return
	}
	// _, err = db.DB.Exec(`DELETE FROM token_blacklist WHERE user_id = $1
	// `, userID)
	// if err != nil {
	// 	http.Error(w, "Error deleting user tokens", http.StatusInternalServerError)
	// 	return
	// }
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User deleted successfully"})
}
