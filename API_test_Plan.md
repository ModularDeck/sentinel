# ============================================
# SENTINEL API TEST FLOW
# ============================================
# Your data:
- user_id: 3, tenant_id: 3, team_id: 3
- email: user3@example.com
# ============================================

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6InVzZXIzQGV4YW1wbGUuY29tIiwidGVuYW50X2lkIjozLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3Njk3NzUyNDUsImp0aSI6IjBjMjY4NDk1LThkMjMtNDcyOS1hZjViLTk2N2NiNzQ3OGQ0YSIsImlhdCI6MTc2OTY4ODg0NX0.cVsVuXsma4n4jYKnbaqutifdv-zF9drtL9eERvJc9xI"
```

## 1. REGISTER (already done)
```bash
curl -X POST http://localhost:8080/register \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Harshit",
        "email": "user3@example.com",
        "password": "Securepassword1@",
        "tenant_name": "Parshii",
        "tenant_desc": "Description of the firm",
        "team_name": "Example Team",
        "team_desc": "Description of the team",
        "user_role": "admin",
        "team_role": "admin"
    }'
```

## 2. LOGIN (already done)
```bash
curl -X POST http://localhost:8080/login \
    -H "Content-Type: application/json" \
    -d '{
        "email": "user3@example.com",
        "password": "Securepassword1@"
    }'
```

## 3. HEALTH CHECK
```bash
curl http://localhost:8080/health
```

## 4. GET CURRENT USER INFO
```bash
curl -H "Authorization: Bearer $TOKEN" \
    http://localhost:8080/api/userinfo
```

## 5. GET USER BY ID
```bash
curl -H "Authorization: Bearer $TOKEN" \
    http://localhost:8080/api/user/3
```

## 6. GET ALL USERS IN TENANT
```bash
curl -H "Authorization: Bearer $TOKEN" \
    http://localhost:8080/api/user/tenant/3
```

## 7. GET ALL TEAMS
```bash
curl -H "Authorization: Bearer $TOKEN" \
    http://localhost:8080/api/team
```

## 8. CREATE NEW TEAM
```bash
curl -X POST http://localhost:8080/api/team \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Marketing Team",
        "description": "Marketing department"
    }'
```

## 9. UPDATE TEAM (use team_id from step 8 response)
```bash
curl -X PUT http://localhost:8080/api/team \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "id": 4,
        "name": "Marketing Team Updated",
        "description": "Updated marketing department"
    }'
```

## 10. CREATE NEW USER IN TENANT
```bash
curl -X POST http://localhost:8080/api/user \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "John Doe",
        "email": "john@example.com",
        "password": "Securepassword1@",
        "team_name": "Marketing Team Updated",
        "team_desc": "Marketing department",
        "user_role": "member",
        "team_role": "member"
    }'
```

## 11. UPDATE USER (use user_id from step 10 response)
```bash
curl -X PUT http://localhost:8080/api/user \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "user_id": 4,
        "name": "John Doe Updated",
        "role": "member"
    }'
```

## 12. GET MODULES
```bash
curl -H "Authorization: Bearer $TOKEN" \
    http://localhost:8080/api/modules
```

## 13. REQUEST PASSWORD RESET
```bash
curl -X POST http://localhost:8080/request-password-reset \
    -H "Content-Type: application/json" \
    -d '{
        "email": "user3@example.com"
    }'
```

## 14. RESEND VERIFICATION EMAIL
```bash
curl -X POST http://localhost:8080/webhooks/resend-email \
    -H "Content-Type: application/json" \
    -d '{
        "email": "user3@example.com"
    }'
```

## 15. DELETE USER (use user_id from step 10)
```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
    http://localhost:8080/api/user/4
```

## 16. DELETE TEAM (use team_id from step 8)
```bash
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
    http://localhost:8080/api/team/4
```

## 17. LOGOUT (run last - invalidates token)
```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
    http://localhost:8080/logout
```