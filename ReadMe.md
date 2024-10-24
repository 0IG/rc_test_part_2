# Authentication System

A secure authentication system built with Node.js/Express backend and React frontend, featuring JWT tokens and refresh token rotation.

## Folder Structure
root
│
├── client (React frontend)
│ ├── package.json
│ └── node_modules
│
├── server (Node.js backend)
│ ├── package.json
│ ├── .env (you need to create this)
│ └── node_modules
│
└── package.json (root)

## Environment Setup

1. Create a `.env` file in the server directory with the following variables:
PORT=3001
SECRET_KEY=your_jwt_secret_key_here
REFRESH_SECRET_KEY=your_refresh_token_secret_here
NODE_ENV=development

## Required Dependencies

### Server Dependencies
```
{
  "dependencies": {
    "bcrypt": "^5.x.x",
    "cookie-parser": "^1.x.x",
    "cors": "^2.x.x",
    "dotenv": "^16.x.x",
    "express": "^4.x.x",
    "express-rate-limit": "^6.x.x",
    "jsonwebtoken": "^9.x.x",
    "morgan": "^1.x.x"
  }
}

How to Run This Application (At the ROOT of the FOLDER)

Install dependencies for the client and server:
npm run install:client
npm run install:server

Start the application:
npm run start

Once running:

React frontend: http://localhost:3000
Express backend: http://localhost:3001/testing

API Endpoints
Public Routes

POST /register - Register a new user
POST /login - Login and receive tokens
GET /testing - Test if server is running

Protected Routes (Requires Authentication)

GET /protected - Test protected route
GET /user-info - Get current user information
POST /token - Refresh access token
DELETE /logout - Logout current session
DELETE /logout-all - Logout all sessions

Admin Only Routes

GET /users - Get all users
POST /admin/create-user - Create a new user

Authentication Flow

Registration:

Password must meet complexity requirements (min 8 chars, uppercase, lowercase, number, special char)
Returns 201 on success

Login:

Returns an access token (15min validity)
Sets a refresh token as an HTTP-only cookie (3hr validity)

Token Refresh:

Uses the refresh token cookie to get a new access token
Implements token rotation for security

Logout:

Invalidates current session
Clears refresh token cookie
Adds access token to blacklist

Security Features

Password hashing with bcrypt
Rate limiting (100 requests per 15 minutes)
Token blacklisting
CORS protection
Secure cookie configuration:

HTTP-only
Secure in production
Strict same-site policy
3-hour expiration


Role-based access control (user, moderator, admin)
Regular cleanup of expired blacklisted tokens

Frontend Integration
For frontend integration, set up your Axios instance or fetch calls with:
// Add the access token to all protected requests
headers: {
  'Authorization': `Bearer ${accessToken}`
}

// Axios default config
axios.defaults.withCredentials = true; // Important for cookies
