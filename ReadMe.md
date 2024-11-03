# Authentication System

A secure authentication system built with Node.js/Express backend and React frontend, featuring JWT tokens and refresh token rotation.

## Folder Structure
```
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
```
## Environment Setup

Create a `.env` file in the server directory with the following variables:

* PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n_____Your Private Key_____\n-----END RSA PRIVATE KEY-----"

* PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n___Your Public Key___\n-----END PUBLIC KEY-----"

* REFRESH_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n++++Your Refresh Private Key++++\n-----END RSA PRIVATE KEY-----"

* PORT = 3001

## Generating RS256 Keys

#### Run the following in your bash terminal:

`openssl genrsa -out private.key 2048`

`openssl rsa -in private.key -pubout -out public.key`

You can now cat private.key & public key and plug them into your .env file.




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
```
## How to Run This Application (At the ROOT of the FOLDER)

### Install dependencies for the client and server:
`npm run install:client`

`npm run install:server`

#### Start the application:
`npm run start`

### Once running:

React frontend: http://localhost:3000
Express backend: http://localhost:3001/testing

## API Endpoints
### Public Routes

* POST /register - Register a new user
* POST /login - Login and receive tokens
* GET /testing - Test if server is running

### Protected Routes (Requires Authentication)

* GET /protected - Test protected route
* GET /user-info - Get current user information
* POST /token - Refresh access token

* DELETE /logout - Logout current session

* DELETE /logout-all - Logout all sessions

### Admin Only Routes

GET /users - Get all users

POST /admin/create-user - Create a new admin

## Authentication Flow

### Registration:

Password must meet complexity requirements (min 8 chars, uppercase, lowercase, number, special char)
Returns 201 on success

### Login:

Returns an access token (15min validity)
Sets a refresh token as an HTTP-only cookie (3hr validity)

### Token Refresh:

Uses the refresh token cookie to get a new access token
Implements token rotation for security

### Logout:

* Invalidates current session
* Clears refresh token cookie
* Adds access token to blacklist

## Security Features

* Password hashing with bcrypt
* Rate limiting (100 requests per 15 minutes)
* Token blacklisting
* CORS protection

### Secure cookie configuration:

*  HTTP-only
* Strict same-site policy
* 3-hour expiration


## Important Links
### [Sources](https://joinpursuit.notion.site/Sources-125d2512d7ba806bb762ebfd7f08c660)
###  [Trello Board](https://trello.com/invite/b/671acb59948fbe8c03727cc0/ATTI549954698c11d8ad09f7c79cd645d54e7B8B4939/red-canary-take-home)
### [JWT.io](https://jwt.io/)