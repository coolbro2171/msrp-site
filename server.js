const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const app = express();

// Middleware to parse form data and serve files
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

// Session Configuration
app.use(session({
    secret: 'secure-dev-key-789',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 3600000 } // Session expires in 1 hour
}));

const DATA_FILE = path.join(__dirname, 'users.json');

// Helper function: Reads the users.json file
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

// Helper function: Saves the user list back to users.json
function saveUsers(users) {
    try {
        fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
    } catch (err) {
        console.error("Save error:", err);
    }
}

// Security Middleware: Checks if a user is logged in
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
    if (req.session.role === 'Admin') {
        res.sendFile(path.join(__dirname, 'admin.html'));
    } else {
        res.status(403).send('Access Denied: Admins Only. <a href="/dashboard">Go Back</a>');
    }
});

// --- API ROUTES ---

// Gets the current user's profile info
app.get('/api/me', protect, (req, res) => {
    res.json({ 
        username: req.session.username, 
        role: req.session.role 
    });
});

// Gets all users (Admin only)
app.get('/api/users', protect, (req, res) => {
    if (req.session.role !== 'Admin') return res.sendStatus(403);
    const users = loadUsers();
    res.json(users.map(u => ({ username: u.username, role: u.role })));
});

// Promotes a user to Admin (Admin only)
app.post('/api/promote-user/:username', protect, (req, res) => {
    if (req.session.role !== 'Admin') return res.sendStatus(403);
    let users = loadUsers();
    let user = users.find(u => u.username === req.params.username);
    if (user) {
        user.role = 'Admin';
        saveUsers(users);
        res.sendStatus(200);
    } else {
        res.status(404).send('User not found');
    }
});

// Deletes a user (Admin only)
app.delete('/api/delete-user/:username', protect, (req, res) => {
    if (req.session.role !== 'Admin') return res.sendStatus(403);
    let users = loadUsers();
    users = users.filter(u => u.username !== req.params.username);
    saveUsers(users);
    res.sendStatus(200);
});

// --- AUTHENTICATION LOGIC ---

app.post('/register', async (req, res) => {
    try {
        const users = loadUsers();
        if (users.find(u => u.username === req.body.username)) {
            return res.send('Username exists. <a href="/register">Try again</a>');
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        
        // The very first user to register, or the specific "Admin" user, gets the Admin role
        const role = (users.length === 0 || req.body.username === "Admin") ? 'Admin' : 'User';

        users.push({
            username: req.body.username,
            password: hashedPassword,
            role: role
        });

        saveUsers(users);

        req.session.isLoggedIn = true;
        req.session.username = req.body.username;
        req.session.role = role;
        res.redirect('/dashboard');
    } catch {
        res.status(500).send('Error during registration.');
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const users = loadUsers();
    const user = users.find(u => u.username === username);
    
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.isLoggedIn = true;
        req.session.username = username;
        req.session.role = user.role;

        if (user.role === 'Admin') {
            res.redirect('/admin');
        } else {
            res.redirect('/dashboard');
        }
    } else {
        res.status(401).send('Invalid login. <a href="/">Back to Login</a>');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// --- START SERVER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
