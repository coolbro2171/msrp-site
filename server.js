const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');

const app = express();

app.set('trust proxy', 1); 

// --- DATABASE CONNECTION ---
const MONGODB_URI = "mongodb+srv://cool_bro2171:Leonardo3@msrp-site.axszmf7.mongodb.net/MSRP_Database?retryWrites=true&w=majority&appName=MSRP-Site";

mongoose.connect(MONGODB_URI)
    .then(() => console.log("MongoDB Connected"))
    .catch(err => console.error("MongoDB Error:", err));

// --- USER SCHEMA ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['User', 'Staff', 'Admin', 'Management', 'Owner'], default: 'User' },
    isBanned: { type: Boolean, default: false },
    isDeveloper: { type: Boolean, default: false },
    isDatabaseAccess: { type: Boolean, default: false },
    isStaffTrainer: { type: Boolean, default: false },
    isFounder: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

// --- MIDDLEWARE ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(session({
    secret: 'msrp-secure-v3-789',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ 
        mongoUrl: MONGODB_URI,
        collectionName: 'sessions' 
    }),
    cookie: { 
        secure: false, 
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 
    }
}));

// --- API: AUTH & ADMIN ---

// Check login status for frontend
app.get('/api/check-auth', (req, res) => {
    if (req.session && req.session.isLoggedIn) {
        res.json({ loggedIn: true, username: req.session.username });
    } else {
        res.json({ loggedIn: false });
    }
});

// Admin Only: Get all users
app.get('/api/admin/users', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).send('Unauthorized');
    
    try {
        // Only allow Admin, Management, or Owner to see this list
        const currentUser = await User.findOne({ username: req.session.username });
        if (!['Admin', 'Management', 'Owner'].includes(currentUser.role)) {
            return res.status(403).send('Forbidden');
        }

        const users = await User.find({}, '-password'); // Exclude passwords for safety
        res.json(users);
    } catch (err) {
        res.status(500).send('Error fetching users');
    }
});

// Admin Only: Update User Roles/Badges
app.post('/api/admin/update-user', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).send('Unauthorized');

    try {
        const { targetUsername, updates } = req.body;
        
        // Ensure the person doing the update is an Admin+
        const adminUser = await User.findOne({ username: req.session.username });
        if (!['Admin', 'Management', 'Owner'].includes(adminUser.role)) {
            return res.status(403).send('Unauthorized access');
        }

        await User.findOneAndUpdate({ username: targetUsername }, updates);
        res.sendStatus(200);
    } catch (err) {
        res.status(500).send('Update failed');
    }
});

// --- AUTH ROUTES ---
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (user && await bcrypt.compare(password, user.password)) {
            if (user.isBanned) return res.status(403).send('Banned');

            req.session.username = user.username;
            req.session.isLoggedIn = true;

            req.session.save((err) => {
                if (err) return res.status(500).send("Login Error");
                res.redirect('/dashboard');
            });
        } else {
            res.status(401).send('Invalid Credentials');
        }
    } catch (err) {
        res.status(500).send("Server Error");
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.clearCookie('connect.sid');
    res.redirect('/');
});

// --- PUBLIC ROUTES ---

// Main Info/Landing Page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Login Page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Register Page
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});


// --- PROTECTED ROUTES (Require Login) ---

// Staff Dashboard
app.get('/dashboard', (req, res) => {
    if (req.session && req.session.isLoggedIn) {
        res.sendFile(path.join(__dirname, 'dashboard.html'));
    } else {
        res.redirect('/login');
    }
});

// Server Documents
app.get('/documents', (req, res) => {
    if (req.session && req.session.isLoggedIn) {
        res.sendFile(path.join(__dirname, 'documents.html'));
    } else {
        res.redirect('/login');
    }
});

// Account Settings
app.get('/settings', (req, res) => {
    if (req.session && req.session.isLoggedIn) {
        res.sendFile(path.join(__dirname, 'settings.html'));
    } else {
        res.redirect('/login');
    }
});


// Admin Panel (Only for high-ranking staff)
app.get('/admin', (req, res) => {
    if (req.session && req.session.isLoggedIn) {
        res.sendFile(path.join(__dirname, 'admin.html'));
    } else {
        res.redirect('/login');
    }
});


// --- FALLBACK ROUTE ---

// This catches any 404/Unknown pages and sends them to the Info Page
app.get('*', (req, res) => {
    res.redirect('/');
});

app.get('/admin', (req, res) => {
    if (req.session.isLoggedIn) {
        res.sendFile(path.join(__dirname, 'admin.html'));
    } else {
        res.redirect('/login');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MSRP running on port ${PORT}`));



