DRUVASOLUTION CUSTOMER LOGIN BACKEND

This is the first backend stage for the DruvaSolution website.
It provides:
- Customer creation (temporary setup endpoint)
- Secure password hashing with bcryptjs
- Customer login
- JWT session token
- Protected /api/me endpoint

LOCAL SETUP
1. Install Node.js LTS.
2. Open Command Prompt in this folder.
3. Run: npm install
4. Copy .env.example to .env
5. Set JWT_SECRET to a long random value.
6. Run: npm start
7. Test: http://localhost:3000/api/health

CREATE DEMO CUSTOMER
Use POST /api/setup/customer with JSON:
{
  "name": "Demo Customer",
  "email": "customer@example.com",
  "username": "customer1",
  "password": "Demo@123"
}

LOGIN
POST /api/login
{
  "username": "customer1",
  "password": "Demo@123"
}

IMPORTANT
The setup endpoint is intentionally temporary for development. Before production,
we will replace it with the real Admin Panel and proper admin authentication.
For production hosting we should move customer data to a managed database rather
than keeping JSON storage on a server with ephemeral disk.
