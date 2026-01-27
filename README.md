# Sentinel

A modular, multi-tenant user management system written in Go. Sentinel provides a complete RBAC (Role-Based Access Control) solution with JWT authentication, team management, and enterprise-ready security features.

*"To watch over as a guard!"*

## Features

- **Multi-Tenant Architecture** - Isolated tenant organizations with teams and users
- **JWT Authentication** - Secure token-based authentication with blacklist support
- **Role-Based Access Control** - Admin/member roles with permission checks
- **Password Security** - bcrypt hashing with complexity requirements
- **Session Management** - Active session tracking with single-session enforcement (optional)
- **Login Audit Logging** - Track all login attempts with IP addresses
- **Password Reset** - Secure token-based password reset flow
- **Email Verification** - Optional email confirmation for new users
- **Rate Limiting** - Configurable per-user rate limiting
- **CORS Support** - Configurable allowed origins

## Tech Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.23+ |
| Web Framework | Gorilla Mux |
| Database | PostgreSQL |
| Authentication | JWT (HS256) |
| Password Hashing | bcrypt |

## Quick Start

### Prerequisites

- Go 1.23+
- PostgreSQL
- (Optional) Docker & Kubernetes for deployment

### Environment Variables

```bash
# Required
DATABASE_URL=postgres://user:password@localhost:5432/sentinel?sslmode=disable
JWT_SECRET=your-secure-secret-key-min-32-chars

# Optional
REQUIRE_EMAIL_VERIFICATION=false  # Set to "true" to require email verification
SINGLE_SESSION=false              # Set to "true" to enforce single active session per user
APP_BASE_URL=http://localhost:8080
EMAIL_VERIFIED_REDIRECT_URL=      # URL to redirect after email verification
CORS_ALLOWED_ORIGINS=             # Comma-separated list of allowed origins
RATE_LIMIT=100                    # Requests per second
BURST_LIMIT=300                   # Burst limit for rate limiting
```

### Run Locally

```bash
# Clone the repository
git clone https://github.com/your-org/sentinel.git
cd sentinel

# Set environment variables
export DATABASE_URL="postgres://user:password@localhost:5432/sentinel?sslmode=disable"
export JWT_SECRET="your-secure-secret-key-change-in-production"

# Run the server
go run cmd/server/main.go

# Or build and run
make run
```

### Using Kubernetes (Minikube)

```bash
# Start everything
make all

# Or step by step
make up           # Start Minikube
make build-image  # Build Docker image
make postgres     # Deploy PostgreSQL
make migrate      # Run database migrations
make app          # Deploy Sentinel
make port-forward # Forward port 8080
```

## Database Schema

Sentinel requires the following tables. Run the migration scripts in `k8s/base/` or create manually:

```sql
-- Core tables
CREATE TABLE tenants (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'member',
    mobile VARCHAR(20),
    email_confirmed BOOLEAN DEFAULT FALSE,
    confirmation_token VARCHAR(255),
    reset_token VARCHAR(255),
    reset_token_expiry TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE teams (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);

CREATE TABLE user_teams (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams(id) ON DELETE CASCADE,
    role VARCHAR(50) DEFAULT 'member',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, team_id)
);

-- Session management
CREATE TABLE token_blacklist (
    id SERIAL PRIMARY KEY,
    token TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE active_sessions (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    tenant_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    last_ip VARCHAR(45),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(email, tenant_id)
);

-- Audit logging
CREATE TABLE login_audit_logs (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    tenant_id INTEGER,
    ip_address VARCHAR(45),
    login_status VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Optional: Module management
CREATE TABLE modules (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER REFERENCES tenants(id),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(tenant_id, name)
);
```

## API Reference

### Public Endpoints

#### Health Check
```bash
GET /health
```

#### Register
```bash
POST /register
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "SecureP@ss123",
  "tenant_name": "Acme Corp",
  "tenant_desc": "Our organization",
  "team_name": "Engineering",
  "user_role": "admin"
}
```

#### Login
```bash
POST /login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecureP@ss123"
}

# Response
{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

#### Logout
```bash
POST /logout
Authorization: Bearer <token>
```

#### Request Password Reset
```bash
POST /request-password-reset
Content-Type: application/json

{
  "email": "john@example.com"
}
```

#### Reset Password
```bash
POST /reset-password
Content-Type: application/json

{
  "token": "reset-token-from-email",
  "new_password": "NewSecureP@ss123"
}
```

### Protected Endpoints (Require JWT)

All `/api/*` endpoints require the `Authorization: Bearer <token>` header.

#### Get Current User Info
```bash
GET /api/userinfo
```

#### Get User by ID
```bash
GET /api/user/{id}
```

#### Update User (Admin Only)
```bash
PUT /api/user
Content-Type: application/json

{
  "user_id": 1,
  "name": "Updated Name",
  "role": "admin"
}
```

#### Get Users by Tenant (Admin Only)
```bash
GET /api/user/tenant/{tenant_id}
```

#### Delete User (Admin Only)
```bash
DELETE /api/user/{id}
```

#### Create User in Tenant (Admin Only)
```bash
POST /api/user
Content-Type: application/json

{
  "name": "Jane Doe",
  "email": "jane@example.com",
  "password": "SecureP@ss123",
  "team_name": "Sales",
  "user_role": "member"
}
```

#### List Teams
```bash
GET /api/team
```

#### Create Team (Admin Only)
```bash
POST /api/team
Content-Type: application/json

{
  "name": "Marketing",
  "description": "Marketing team"
}
```

#### Update Team (Admin Only)
```bash
PUT /api/team
Content-Type: application/json

{
  "id": 1,
  "name": "Updated Team Name",
  "description": "Updated description"
}
```

#### Delete Team (Admin Only)
```bash
DELETE /api/team/{id}
```

#### Get Modules
```bash
GET /api/modules
```

## Security Best Practices

1. **JWT Secret**: Always set a strong `JWT_SECRET` in production (minimum 32 characters)
2. **Database**: Use SSL connections in production (`sslmode=require`)
3. **CORS**: Configure `CORS_ALLOWED_ORIGINS` to only allow your frontend domains
4. **Rate Limiting**: Adjust `RATE_LIMIT` and `BURST_LIMIT` based on your needs
5. **Email Verification**: Enable `REQUIRE_EMAIL_VERIFICATION=true` for production
6. **Single Session**: Consider enabling `SINGLE_SESSION=true` for sensitive applications

## Project Structure

```
sentinel/
├── cmd/
│   └── server/
│       └── main.go          # Application entry point
├── internal/
│   ├── auth/
│   │   ├── auth.go          # JWT generation and validation
│   │   └── middleware.go    # Auth middleware, rate limiting, CORS
│   ├── db/
│   │   └── db.go            # Database connection
│   ├── handlers/
│   │   ├── login.go         # Login, password reset, email verification
│   │   ├── logout.go        # Logout handler
│   │   ├── users.go         # User CRUD operations
│   │   └── team.go          # Team management
│   └── models/
│       └── user.go          # Data models
├── k8s/                     # Kubernetes manifests
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
