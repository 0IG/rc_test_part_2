require('dotenv').config();
const express = require("express");
const jwt = require("jsonwebtoken");
const logger = require("morgan");
const cors = require("cors");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const app = express();

// Environment variables
const privateKey = process.env.PRIVATE_KEY; 
const publicKey = process.env.PUBLIC_KEY;
const refreshPrivateKey = process.env.REFRESH_SECRET_KEY || privateKey;
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(logger("dev"));
app.use(express.json());
app.use(cookieParser());
app.use(helmet());
// Blacklist
let tokenBlacklist = new Set();

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

let users = [];
let refreshTokens = new Set();

// Hardcoded list of initial administrators
const administrators = [
  { id: 1, username: "admin", password: "password", role: "admin" },
  { id: 2, username: "isaac", password: "iHeartCoffee1337", role: "user" },
  { id: 3, username: "redcanary", password: "thisIsaacGuyIsPrettyCool", role: "moderator" },
];

// Helper functions
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}

async function initializeUsers() {
  for (let user of administrators) {
    const hashedPassword = await hashPassword(user.password);
    users.push({ ...user, password: hashedPassword });
  }
  console.log("Users initialized with hashed passwords");
}

function generateAccessToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    privateKey,
    { expiresIn: '15m',
      algorithm: 'RS256'
     }
  );
}

// Middleware functions
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);
  
  jwt.verify(token, publicKey, {algorithm: ['RS256']},(err, user) => {
    if (err) return res.sendStatus(403);

    if (tokenBlacklist.has(token)) {
      return res.sendStatus(403);
    }

    req.user = user;
    req.token = token;
    next();
  });
}

function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ message: "Access denied" });
    }
    next();
  };
}

function cleanupTokenBlacklist() {
  tokenBlacklist.forEach(token => {
    try {
      jwt.verify(token, publicKey, { algorithm: ['RS256'] });
    } catch (err) {
      tokenBlacklist.delete(token);
    }
  });
}

setInterval(cleanupTokenBlacklist, 1000 * 60 * 15 ); // 15 minutes

// Routes

// Register a new user
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  
  // Password complexity check
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({ message: "Password does not meet complexity requirements", 
      required: {
        "Must be at least 8 characters long": password.length >= 8,
        "Must contain at least one uppercase letter": /[A-Z]/.test(password),
        "Must contain at least one lowercase letter": /[a-z]/.test(password),
        "Must contain at least one number": /\d/.test(password),
        "Must contain at least one special character": /[@$!%*?&]/.test(password)
      }});
  }
  
  try {
    const hashedPassword = await hashPassword(password);
    const newUser = { id: users.length + 1, username, password: hashedPassword, role: "user" };
    users.push(newUser);
    console.log("New user registered:", { id: newUser.id, username: newUser.username.toString(), role: newUser.role });
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error registering user" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  
  const user = users.find(u => u.username === username);
  
  if (!user) return res.status(401).json({ message: "Invalid credentials" });
  
  try {
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (isMatch) {
      const accessToken = generateAccessToken(user);
      const refreshToken = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        refreshPrivateKey,
        {algorithm: 'RS256'}
      );
      refreshTokens.add(refreshToken);
      
      res.cookie('refreshToken', refreshToken, { 
        httpOnly: true, 
        secure: false, 
        sameSite: 'lax', // lax, strict, none (lax for development) / (strict for production)
        path: '/',
        maxAge: 1000 * 60 * 60 * 3 // 3 hours
      });
      
      res.json({ accessToken });
    } else {
      res.status(401).json({ message: "Invalid credentials"});
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error during login" });
  }
});

// Token refresh
app.post("/token", (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokens.has(refreshToken)) return res.sendStatus(403);
  
  jwt.verify(refreshToken, refreshPrivateKey, {algorithm: ['RS256']}, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ id: user.id, username: user.username, role: user.role });
    res.json({ accessToken: accessToken });
  });
});

// Logout
app.delete("/logout", (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  refreshTokens.delete(refreshToken);

  tokenBlacklist.add(req.token)

  res.clearCookie('refreshToken');
  res.sendStatus(204);
});
// Logout 
app.delete("/logout-all", authenticateToken, (req, res) => {
  const userId = req.user.id;

  refreshTokens = new Set([...refreshTokens].filter(token => {
    const decoded = jwt.decode(token);
    return decoded.id !== userId;
  }));

  userTokens.forEach(token => tokenBlacklist.add(token));
  res.clearCookie('refreshToken');
  res.sendStatus(204);
})

// Protected route
app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "Welcome to the protected route!", user: req.user });
});

// Get all users (admin only)
app.get("/users", authenticateToken, authorizeRole("admin"), (req, res) => {
  // If you'd like to see hashed passwords, uncomment the following line and comment the line current safeUsers func.
  // const safeUsers = users.map(({ id, username, password, role }) => ({ id, username, role }));
  const safeUsers = users.map(({ id, username, role }) => ({ id, username, role }));
  res.json(safeUsers);
});

// Get user info
app.get("/user-info", authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({ id: user.id, username: user.username, role: user.role });
});

// Create new user (admin only)
app.post("/admin/create-user", authenticateToken, authorizeRole("admin"), async (req, res) => {
  const { username, password, role } = req.body;
  const validRoles = ["user", "moderator", "admin"];
  
  // Check if all required fields are provided
  if (!username || !password || !role) {
    return res.status(400).json({ message: "Username, password, and role are required" });
  }
  
  // Check if the role is valid
  if (!validRoles.includes(role)) {
    return res.status(400).json({ message: "Invalid role" });
  }
  
  // Check if the username already exists
  if (users.some(user => user.username === username)) {
    return res.status(409).json({ message: "Username already exists" });
  }
  
  try {
    // Hash the password
    const hashedPassword = await hashPassword(password);
    
    // Create the new user
    const newUser = {
      id: users.length + 1,
      username,
      password: hashedPassword,
      role
    };
    
    // Add the new user to the users array
    users.push(newUser);
    
    // Log the new user creation (excluding the password)
    console.log("New user created by admin:", { id: newUser.id, username: newUser.username, role: newUser.role });
    
    // Send a success response
    res.status(201).json({ 
      message: "User created successfully", 
      user: { id: newUser.id, username: newUser.username, role: newUser.role }
    });
  } catch (error) {
    console.error("Error creating new user:", error);
    res.status(500).json({ message: "Error creating user" });
  }
});

// Test route
app.get("/testing", (req, res) => {
  res.send("App is working!");
});

// Initialize and start the server
initializeUsers().then(() => {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log("Private key:", privateKey);
    console.log("Public key:", publicKey);
    console.log("Refresh private key:", refreshPrivateKey);
  });
});
