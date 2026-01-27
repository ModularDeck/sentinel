package models

import (
	"time"
)

// Tenant represents an organization or company
type Tenant struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type User struct {
	ID        int       `json:"id"`
	TenantID  int       `json:"tenant_id"` // Reference to the tenant
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Password  string    `json:"-"` // do not expose password in API responses
	Role      string    `json:"role"`
	Team      Team      `json:"team,omitempty"` // Optional team association
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Team struct {
	ID          int       `json:"id"`
	TenantID    int       `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
type UserTeam struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	TeamID    int       `json:"team_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Req_User_Login represents the request body for user registration
type Req_User_Login struct {
	UserName     string `json:"name"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	TenantName   string `json:"tenant_name,omitempty"`
	TenantDesc   string `json:"tenant_desc,omitempty"`
	TeamName     string `json:"team_name,omitempty"`
	TeamDesc     string `json:"team_desc,omitempty"`
	UserTeamRole string `json:"team_role,omitempty"`
	UserRole     string `json:"user_role,omitempty"`
	Mobile       string `json:"mobile,omitempty"`
}

// Module represents a feature module that can be enabled/disabled per tenant
type Module struct {
	ID          int       `json:"id"`
	TenantID    int       `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ActiveSession represents a user's active session
type ActiveSession struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	TenantID  int       `json:"tenant_id"`
	Token     string    `json:"-"`
	LastIP    string    `json:"last_ip"`
	UpdatedAt time.Time `json:"updated_at"`
}

// LoginAuditLog represents a record of login attempts
type LoginAuditLog struct {
	ID          int       `json:"id"`
	Email       string    `json:"email"`
	TenantID    *int      `json:"tenant_id,omitempty"`
	IPAddress   string    `json:"ip_address"`
	LoginStatus string    `json:"login_status"` // SUCCESS or FAILED
	CreatedAt   time.Time `json:"created_at"`
}
