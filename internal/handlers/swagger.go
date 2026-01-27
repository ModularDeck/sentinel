package handlers

import (
	"net/http"
)

// SwaggerUIHandler serves the Swagger UI interface
func SwaggerUIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(swaggerUIHTML))
}

// SwaggerSpecHandler serves the OpenAPI specification
func SwaggerSpecHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.Write([]byte(swaggerSpec))
}

const swaggerUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    <style>
        html { box-sizing: border-box; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin: 0; background: #fafafa; }
        .swagger-ui .topbar { display: none; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {
            SwaggerUIBundle({
                url: "/swagger.yaml",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.SwaggerUIStandalonePreset
                ],
                layout: "BaseLayout"
            });
        };
    </script>
</body>
</html>`

const swaggerSpec = `openapi: 3.0.3
info:
  title: Sentinel API
  description: |
    A modular, multi-tenant user management system with JWT authentication, 
    role-based access control, and enterprise-ready security features.
    
    ## Authentication
    Most endpoints require JWT authentication. Include the token in the Authorization header:
    ` + "`" + `Authorization: Bearer <your-jwt-token>` + "`" + `
    
    ## Multi-Tenancy
    Users belong to tenants (organizations). The tenant context is extracted from the JWT token.
    
    ## Roles
    - ` + "`" + `admin` + "`" + ` - Full access to tenant resources
    - ` + "`" + `member` + "`" + ` - Limited access based on permissions
  version: 1.0.0
  license:
    name: MIT
    url: https://opensource.org/licenses/MIT
  contact:
    name: ModularDeck
    url: https://github.com/ModularDeck/ModSentinelDeck

servers:
  - url: http://localhost:8080
    description: Local development server

tags:
  - name: Health
    description: Health check endpoints
  - name: Authentication
    description: Login, logout, and registration
  - name: Password
    description: Password reset operations
  - name: Email Verification
    description: Email verification endpoints
  - name: Users
    description: User management operations
  - name: Teams
    description: Team management operations
  - name: Modules
    description: Feature module management

paths:
  /health:
    get:
      tags:
        - Health
      summary: Health check
      description: Check if the server is running
      operationId: healthCheck
      responses:
        '200':
          description: Server is healthy
          content:
            text/plain:
              schema:
                type: string
                example: OK

  /register:
    post:
      tags:
        - Authentication
      summary: Register a new user and tenant
      description: Creates a new tenant, user, and default team. The first user is assigned admin role.
      operationId: registerUser
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RegisterRequest'
      responses:
        '201':
          description: User registered successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegisterResponse'
        '400':
          description: Invalid input or validation error
        '409':
          description: Tenant or user already exists

  /login:
    post:
      tags:
        - Authentication
      summary: Login and get JWT token
      description: Authenticates a user and returns a JWT token.
      operationId: login
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
      responses:
        '200':
          description: Login successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LoginResponse'
        '401':
          description: Invalid credentials

  /logout:
    post:
      tags:
        - Authentication
      summary: Logout and invalidate token
      description: Logs out the user by blacklisting the token.
      operationId: logout
      security:
        - bearerAuth: []
      responses:
        '200':
          description: Logout successful
        '401':
          description: Invalid or missing token

  /request-password-reset:
    post:
      tags:
        - Password
      summary: Request password reset
      description: Initiates password reset by generating a reset token (expires in 30 min).
      operationId: requestPasswordReset
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - email
              properties:
                email:
                  type: string
                  format: email
      responses:
        '200':
          description: Reset request processed

  /reset-password:
    post:
      tags:
        - Password
      summary: Reset password with token
      description: Resets the user's password using a valid reset token.
      operationId: resetPassword
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - token
                - new_password
              properties:
                token:
                  type: string
                new_password:
                  type: string
                  minLength: 8
      responses:
        '200':
          description: Password reset successful
        '400':
          description: Invalid or expired token

  /webhooks/verify-email:
    get:
      tags:
        - Email Verification
      summary: Verify email address
      description: Verifies a user's email using the confirmation token.
      operationId: verifyEmail
      parameters:
        - name: token
          in: query
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Email verified successfully
        '400':
          description: Invalid or expired token

  /webhooks/resend-email:
    post:
      tags:
        - Email Verification
      summary: Resend verification email
      description: Generates a new confirmation token and resends verification email.
      operationId: resendVerificationEmail
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - email
              properties:
                email:
                  type: string
                  format: email
      responses:
        '200':
          description: Verification email sent
        '400':
          description: Email already verified
        '404':
          description: User not found

  /api/userinfo:
    get:
      tags:
        - Users
      summary: Get current user info
      description: Returns information about the currently authenticated user.
      operationId: getCurrentUser
      security:
        - bearerAuth: []
      responses:
        '200':
          description: User information
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserInfoResponse'
        '401':
          description: Unauthorized

  /api/user/{id}:
    get:
      tags:
        - Users
      summary: Get user by ID
      description: Returns information about a specific user within the same tenant.
      operationId: getUserById
      security:
        - bearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
      responses:
        '200':
          description: User information
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserInfoResponse'
        '401':
          description: Unauthorized

    delete:
      tags:
        - Users
      summary: Delete user (Admin only)
      description: Deletes a user from the tenant.
      operationId: deleteUser
      security:
        - bearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
      responses:
        '200':
          description: User deleted successfully
        '403':
          description: Forbidden - requires admin role

  /api/user:
    post:
      tags:
        - Users
      summary: Create user in tenant (Admin only)
      description: Creates a new user within the current tenant.
      operationId: createUserInTenant
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateUserRequest'
      responses:
        '201':
          description: User created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegisterResponse'
        '400':
          description: Invalid input

    put:
      tags:
        - Users
      summary: Update user details (Admin only)
      description: Updates user information.
      operationId: updateUser
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UpdateUserRequest'
      responses:
        '200':
          description: User updated successfully
        '401':
          description: Unauthorized
        '404':
          description: User not found

  /api/user/tenant/{tenant_id}:
    get:
      tags:
        - Users
      summary: Get users by tenant (Admin only)
      description: Returns all users belonging to a specific tenant.
      operationId: getUsersByTenant
      security:
        - bearerAuth: []
      parameters:
        - name: tenant_id
          in: path
          required: true
          schema:
            type: integer
      responses:
        '200':
          description: List of users
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TenantUsersResponse'
        '401':
          description: Unauthorized

  /api/team:
    get:
      tags:
        - Teams
      summary: Get all teams (Admin only)
      description: Returns all teams for the current tenant.
      operationId: getTeams
      security:
        - bearerAuth: []
      responses:
        '200':
          description: List of teams
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Team'
        '403':
          description: Forbidden

    post:
      tags:
        - Teams
      summary: Create a new team (Admin only)
      operationId: createTeam
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateTeamRequest'
      responses:
        '201':
          description: Team created successfully
        '403':
          description: Forbidden

    put:
      tags:
        - Teams
      summary: Update a team (Admin only)
      operationId: updateTeam
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UpdateTeamRequest'
      responses:
        '202':
          description: Team updated successfully
        '403':
          description: Forbidden

  /api/team/{id}:
    delete:
      tags:
        - Teams
      summary: Delete a team (Admin only)
      operationId: deleteTeam
      security:
        - bearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
      responses:
        '200':
          description: Team deleted successfully
        '403':
          description: Forbidden

  /api/modules:
    get:
      tags:
        - Modules
      summary: Get tenant modules
      description: Returns feature modules with their active/inactive status.
      operationId: getModules
      security:
        - bearerAuth: []
      responses:
        '200':
          description: List of modules
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Module'

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
      description: JWT token from /login endpoint

  schemas:
    RegisterRequest:
      type: object
      required:
        - name
        - email
        - password
        - tenant_name
      properties:
        name:
          type: string
        email:
          type: string
          format: email
        password:
          type: string
          minLength: 8
        tenant_name:
          type: string
        tenant_desc:
          type: string
        team_name:
          type: string
        team_desc:
          type: string
        user_role:
          type: string
          enum: [admin, member]
        team_role:
          type: string
          enum: [admin, member]
        mobile:
          type: string

    RegisterResponse:
      type: object
      properties:
        message:
          type: string
        user_id:
          type: string
        tenant_id:
          type: string
        team_id:
          type: string

    LoginRequest:
      type: object
      required:
        - email
        - password
      properties:
        email:
          type: string
          format: email
        password:
          type: string

    LoginResponse:
      type: object
      properties:
        token:
          type: string

    UserInfoResponse:
      type: object
      properties:
        user_id:
          type: integer
        user_name:
          type: string
        user_email:
          type: string
        tenant_id:
          type: integer
        tenant_name:
          type: string
        team_id:
          type: integer
        team_name:
          type: string
        role:
          type: string

    CreateUserRequest:
      type: object
      required:
        - name
        - email
        - password
      properties:
        name:
          type: string
        email:
          type: string
          format: email
        password:
          type: string
          minLength: 8
        team_name:
          type: string
        user_role:
          type: string
          enum: [admin, member]
        team_role:
          type: string
          enum: [admin, member]

    UpdateUserRequest:
      type: object
      required:
        - user_id
      properties:
        user_id:
          type: integer
        name:
          type: string
        email:
          type: string
        password:
          type: string
        tenant_name:
          type: string
        team_name:
          type: string
        role:
          type: string

    TenantUsersResponse:
      type: object
      properties:
        tenant:
          type: object
          properties:
            id:
              type: integer
            name:
              type: string
            description:
              type: string
        users:
          type: array
          items:
            $ref: '#/components/schemas/User'

    User:
      type: object
      properties:
        id:
          type: integer
        tenant_id:
          type: integer
        name:
          type: string
        email:
          type: string
        role:
          type: string
        created_at:
          type: string
          format: date-time
        updated_at:
          type: string
          format: date-time

    Team:
      type: object
      properties:
        id:
          type: integer
        name:
          type: string
        description:
          type: string
        tenant_id:
          type: integer

    CreateTeamRequest:
      type: object
      required:
        - name
      properties:
        name:
          type: string
        description:
          type: string

    UpdateTeamRequest:
      type: object
      required:
        - id
        - name
      properties:
        id:
          type: integer
        name:
          type: string
        description:
          type: string

    Module:
      type: object
      properties:
        name:
          type: string
        description:
          type: string
        active:
          type: boolean`
