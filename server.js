const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const app = express();

// --- DATABASE CONNECTION ---
const MONGODB_URI = "mongodb+srv://cool_bro2171:Leonardo3@msrp-site.axszmf7.mongodb.net/MSRP_Database?retryWrites=true&w=majority&appName=MSRP-Site";

mongoose.connect(MONGODB_URI)
    .then(() => console.log("Connected to Cloud Database successfully"))
    .catch(err => console.error("Database connection error:", err));

// Define User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'User' }
});
const User = mongoose.model('User', userSchema);

// --- MIDDLEWARE ---
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(__dirname));

// Optimized Session Setup for Refreshes
app.use(session({
    secret: 'secure-dev-key-789',
    resave: true,                // Forces session update on refresh
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: MONGODB_URI,
        collectionName: 'sessions',
        ttl: 14 * 24 * 60 * 60   // Sessions persist for 14 days
    }),
    cookie: { 
        maxAge: 3600000,         // 1 hour
        secure: false,           // Set to true only if site uses HTTPS (SSL)
        httpOnly: true,
        sameSite: 'lax'          // Essential for keeping session across refreshes
    }
}));

// Protection Middleware
const protect = (req, res, next) => {
    if (req.session.isLoggedIn) {
        next();
    } else {
        res.redirect('/');
    }
};

// --- HTML PAGE ROUTES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/dashboard', protect, (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));

// Admin Route with Database Re-verification
app.get('/admin', protect, async (req, res) => {
    try {
        // Double-check the role directly from the database on page load/refresh
        const user = await User.findOne({ username: req.session.username });
        
        if (user && user.role === 'Admin') {
            res.sendFile(path.join(__dirname, 'admin.html'));
        } else {
            res.status(403).send('Unauthorized. <a href="/dashboard">Go Back</a>');
        }
    } catch (err) {
        res.redirect('/');
    }
});

// --- API ROUTES ---
app.get('/api/me', protect, (req, res) => {
    res.json({ username: req.session.username, role: req.session.role });
});

app.get('/api/users', protect, async (req, res) => {
    if (req.session.role !== 'Admin') return res.sendStatus(403);
    try {
        const users = await User.find({}, 'username role');
        res.json(users);
    } catch (err) {
        res.status(500).send('Error fetching users');
    }
});

app.post('/api/promote-user/:username', protect, async (req, res) => {
    if (req.session.role !== 'Admin') return res.sendStatus(403);
    try {
        await User.findOneAndUpdate({ username: req.params.username }, { role: 'Admin' });
        res.sendStatus(200);
    } catch (err) {
        res.status(500).send('Error promoting user');
    }
});

app.delete('/api/delete-user/:username', protect, async (req, res) => {
    if (req.session.role !== 'Admin') return res.sendStatus(403);
    try {
        await User.findOneAndDelete({ username: req.params.username });
        res.sendStatus(200);
    } catch (err) {
        res.status(500).send('Error deleting user');
    }
});

// --- AUTHENTICATION ---
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.send('User already exists. <a href="/register">Try again</a>');

        const hashedPassword = await bcrypt.hash(password, 10);
        const userCount = await User.countDocuments();
        const role = (userCount === 0 || username === "Admin") ? 'Admin' : 'User';

        const newUser = new User({ username, password: hashedPassword, role });
        await newUser.save();

        req.session.isLoggedIn = true;
        req.session.username = username;
        req.session.role = role;
        res.redirect('/dashboard');
    } catch (err) {
        res.status(500).send('Error during registration.');
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        
        if (user && await bcrypt.compare(password, user.password)) {
            req.session.isLoggedIn = true;
            req.session.username = username;
            req.session.role = user.role;
            res.redirect(user.role === 'Admin' ? '/admin' : '/dashboard');
        } else {
            res.status(401).send('Invalid credentials. <a href="/">Back</a>');
        }
    } catch (err) {
        res.status(500).send('Server error during login.');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// --- START SERVER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server live on port ${PORT}`));
