const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// Session Configuration
app.use(session({
    secret: 'secure-dev-key-789', // A secret key to sign the session ID cookie
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 } // Session expires in 1 hour (in milliseconds)
}));

const DATA_FILE = path.join(__dirname, 'users.json');

// Helper: Load users from file
function loadUsers() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            fs.writeFileSync(DATA_FILE, JSON.stringify([]));
            return [];
        }
        const data = fs.readFileSync(DATA_FILE, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        return [];
    }
}

// Helper: Save users to file
function saveUsers(users) {
    try {
        fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
    } catch (err) {
        console.error("Save error:", err);
    }
}

// Security Middleware: Checks if the user is logged in
const protect = (req, res, next) => {
    if (req.session.isLoggedIn) {
        next();
    } else {
        res.redirect('/');
    }
};

// --- ROUTES ---

// Login Page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Registration Page
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

// Protected Dashboard
app.get('/dashboard', protect, (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// Protected Admin Page
app.get('/admin', protect, (req, res) => {
    if (req.session.username === 'Admin') {
        res.sendFile(path.join(__dirname, 'admin.html'));
    } else {
        res.status(403).send('Access Denied: Admins Only. <a href="/dashboard">Return to Dashboard</a>');
    }
});

// Logout Route
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// --- POST HANDLERS ---

// Register Logic
app.post('/register', async (req, res) => {
    try {
        const users = loadUsers();
        if (users.find(u => u.username === req.body.username)) {
            return res.send('Username already exists. <a href="/register">Try again</a>');
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        users.push({
            username: req.body.username,
            password: hashedPassword
        });

        saveUsers(users);

        // Auto-login after registration
        req.session.isLoggedIn = true;
        req.session.username = req.body.username;
        res.redirect('/dashboard');
    } catch {
        res.status(500).send('Error during registration.');
    }
});

// Login Logic
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const users = loadUsers();
    const user = users.find(u => u.username === username);
    
    if (user && await bcrypt.compare(password, user.password)) {
        // Successful login: Create session
        req.session.isLoggedIn = true;
        req.session.username = username;

        // Redirect based on identity
        if (username === "Admin" && password === "Cool_bro2171") {
            return res.redirect('/admin');
        }
        res.redirect('/dashboard');
    } else {
        res.status(401).send('Invalid credentials. <a href="/">Try again</a>');
    }
});

// --- START SERVER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is live at http://localhost:${PORT}`);
});
