package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"sentinel/internal/auth"
	"sentinel/internal/db"
	"strconv"

	"github.com/gorilla/mux"
)

type TeamRequest struct {
	ID          int    `json:"id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description"`
	TenantID    int    `json:"tenant_id"`
}

func CreateOrUpdateTeamHandler(w http.ResponseWriter, r *http.Request) {
	createOrUpdateTeam(w, r, db.DB) // Pass the global db instance here
}

func createOrUpdateTeam(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	ctx := r.Context()
	role, _ := auth.GetRole(ctx)
	if role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	tenantId, _ := auth.GetTenantID(ctx)
	if tenantId == 0 {
		http.Error(w, "Tenant ID is required", http.StatusBadRequest)
		return
	}

	var req TeamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodPost {
		// Check if a team with the same name and tenant_id already exists
		_, err := db.Exec(`INSERT INTO teams (name, description, tenant_id) VALUES ($1, $2, $3)`,
			req.Name, req.Description, tenantId)
		if err != nil {
			log.Println("Error creating team:", err)
			http.Error(w, "Error creating team", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"message": "Team created successfully"}`))
	} else {
		_, err := db.Exec(`UPDATE teams SET name=$1, description=$2 WHERE id=$3`,
			req.Name, req.Description, req.ID)
		if err != nil {
			http.Error(w, "Error updating team", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"message": "Team updated successfully"}`))
	}
}

func DeleteTeamHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	role, _ := auth.GetRole(ctx)
	if role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	vars := mux.Vars(r)
	teamIDStr := vars["id"]
	teamID, err := strconv.Atoi(teamIDStr)
	if err != nil {
		http.Error(w, "Invalid team ID", http.StatusBadRequest)
		return
	}

	// Step 1: Update user_teams table to remove users from this team
	_, err = db.DB.Exec(`DELETE FROM user_teams WHERE team_id = $1`, teamID)
	if err != nil {
		http.Error(w, "Error dissociating users from team", http.StatusInternalServerError)
		return
	}

	// Step 2: Delete the team
	_, err = db.DB.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	if err != nil {
		http.Error(w, "Error deleting team", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Team deleted successfully"})
}

// GetTeamsByTenantHandler retrieves all teams for a given tenant
func GetTeamsByTenantHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	role, _ := auth.GetRole(ctx)
	if role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	tenantID, _ := auth.GetTenantID(ctx)

	rows, err := db.DB.Query(`SELECT id, name, description FROM teams WHERE tenant_id = $1`, tenantID)
	if err != nil {
		http.Error(w, "Error retrieving teams", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var teams []TeamRequest
	for rows.Next() {
		var team TeamRequest
		if err := rows.Scan(&team.ID, &team.Name, &team.Description); err != nil {
			http.Error(w, "Error scanning team", http.StatusInternalServerError)
			return
		}
		team.TenantID = tenantID // Set the tenant ID for each team
		teams = append(teams, team)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(teams)
}

// ModuleStatus represents the status of a module for a tenant
type ModuleStatus struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Active      bool   `json:"active"`
}

// GetModulesHandler retrieves the list of modules for the tenant
func GetModulesHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantId, _ := auth.GetTenantID(ctx)
	if tenantId == 0 {
		http.Error(w, "Tenant ID is required", http.StatusBadRequest)
		return
	}

	rows, err := db.DB.Query(`
		SELECT name, description, active 
		FROM modules 
		WHERE tenant_id = $1
	`, tenantId)
	if err != nil {
		http.Error(w, "Failed to fetch modules", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var modules []ModuleStatus
	for rows.Next() {
		var mod ModuleStatus
		if err := rows.Scan(&mod.Name, &mod.Description, &mod.Active); err != nil {
			http.Error(w, "Failed to scan module", http.StatusInternalServerError)
			return
		}
		modules = append(modules, mod)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(modules)
}
