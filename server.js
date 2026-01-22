const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const session = require('express-session'); // New library for cookies
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// Configure the session "VIP Pass" settings
app.use(session({
    secret: 'super-secret-key-123', // Change this to any random string
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 } // Pass expires in 1 hour
}));

const DATA_FILE = path.join(__dirname, 'users.json');

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

function saveUsers(users) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
}

// SECURITY GUARD: This function checks if a user has a valid session
const protect = (req, res, next) => {
    if (req.session.isLoggedIn) {
        next(); // User is logged in, let them through
    } else {
        res.redirect('/'); // Not logged in, send to login page
    }
};

// 1. ROUTE: Login Page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 2. ROUTE: Registration Page
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

// 3. SECURE ROUTE: Dashboard (Protected)
app.get('/dashboard', protect, (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// 4. SECURE ROUTE: Admin Page (Protected)
app.get('/admin', protect, (req, res) => {
    if (req.session.username === 'Admin') {
        res.sendFile(path.join(__dirname, 'admin.html'));
    } else {
        res.status(403).send('Access Denied: Admins Only. <a href="/dashboard">Go back</a>');
    }
});

// 5. LOGIC: Register
app.post('/register', async (req, res) => {
    const users = loadUsers();
    if (users.find(u => u.username === req.body.username)) {
        return res.send('User exists. <a href="/register">Try again</a>');
    }
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    users.push({ username: req.body.username, password: hashedPassword });
    saveUsers(users);
    
    // Log them in immediately
    req.session.isLoggedIn = true;
    req.session.username = req.body.username;
    res.redirect('/dashboard');
});

// 6. LOGIC: Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const users = loadUsers();
    const user = users.find(u => u.username === username);
    
    if (user && await bcrypt.compare(password, user.password)) {
        // Create the session
        req.session.isLoggedIn = true;
        req.session.username = username;

        if (username === "Admin" && password === "Cool_bro2171") {
            return res.redirect('/admin');
        }
        res.redirect('/dashboard');
    } else {
        res.status(401).send('Invalid login. <a href="/">Back</a>');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
