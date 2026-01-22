const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// Session Configuration (The "VIP Pass")
app.use(session({
    secret: 'secure-dev-key-789',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 } // 1 hour
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

// Security Middleware: Checks if user is logged in
const protect = (req, res, next) => {
    if (req.session.isLoggedIn) {
        next();
    } else {
        res.redirect('/');
    }
};

// --- HTML PAGE ROUTES ---

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/dashboard', protect, (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/admin', protect, (req, res) => {
    if (req.session.username === 'Admin') {
        res.sendFile(path.join(__dirname, 'admin.html'));
    } else {
        res.status(403).send('Access Denied. <a href="/dashboard">Back</a>');
    }
});

// --- ADMIN API ROUTES (Fixes the 404 Error) ---

app.get('/api/users', protect, (req, res) => {
    if (req.session.username !== 'Admin') return res.status(403).send('Unauthorized');
    const users = loadUsers();
    // Only send usernames to the frontend for safety
    const userList = users.map(u => ({ username: u.username }));
    res.json(userList);
});

app.delete('/api/delete-user/:username', protect, (req, res) => {
    if (req.session.username !== 'Admin') return res.status(403).send('Unauthorized');
    let users = loadUsers();
    users = users.filter(u => u.username !== req.params.username);
    saveUsers(users);
    res.sendStatus(200);
});

// --- POST LOGIC ---

app.post('/register', async (req, res) => {
    try {
        const users = loadUsers();
        if (users.find(u => u.username === req.body.username)) {
            return res.send('Username taken. <a href="/register">Try again</a>');
        }
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        users.push({ username: req.body.username, password: hashedPassword });
        saveUsers(users);
        
        req.session.isLoggedIn = true;
        req.session.username = req.body.username;
        res.redirect('/dashboard');
    } catch {
        res.status(500).send('Error registering.');
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const users = loadUsers();
    const user = users.find(u => u.username === username);
    
    if (user && await bcrypt.compare(password, user.password)) {
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

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// --- START SERVER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
