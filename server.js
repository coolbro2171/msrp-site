const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');

const app = express();

// --- DEPLOYMENT SETTINGS ---
// Required for Render/Cloud stability
app.set('trust proxy', 1); 

// --- DATABASE CONNECTION ---
const MONGODB_URI = "mongodb+srv://cool_bro2171:Leonardo3@msrp-site.axszmf7.mongodb.net/MSRP_Database?retryWrites=true&w=majority&appName=MSRP-Site";

mongoose.connect(MONGODB_URI)
    .then(() => console.log("MSRP Database Connected"))
    .catch(err => console.error("Database Connection Error:", err));

// --- USER SCHEMA ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['User', 'Staff', 'Admin', 'Management', 'Owner'], default: 'User' },
    isBanned: { type: Boolean, default: false },
    isDeveloper: { type: Boolean, default: false },
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
        secure: false, // Set to true if using HTTPS/SSL
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 // 24 Hours
    }
}));

// --- API ENDPOINTS ---

// Check login status for index.html recognition
app.get('/api/check-auth', (req, res) => {
    if (req.session && req.session.isLoggedIn) {
        res.json({ loggedIn: true, username: req.session.username });
    } else {
        res.json({ loggedIn: false });
    }
});

// Admin API: Fetch all users for the panel
app.get('/api/admin/users', async (req, res) => {
    try {
        if (!req.session.isLoggedIn) return res.status(401).json({ error: "Unauthorized" });
        
        const adminUser = await User.findOne({ username: req.session.username });
        if (!['Admin', 'Management', 'Owner'].includes(adminUser.role)) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const users = await User.find({}, '-password'); 
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: "Server Error" });
    }
});

// --- AUTHENTICATION LOGIC ---

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.redirect('/login');
    } catch (err) {
        res.status(400).send("Registration error: User likely already exists.");
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (user && await bcrypt.compare(password, user.password)) {
            if (user.isBanned) return res.status(403).send('Your account is banned.');

            req.session.username = user.username;
            req.session.isLoggedIn = true;

            req.session.save((err) => {
                if (err) return res.status(500).send("Session Save Error");
                res.redirect('/dashboard');
            });
        } else {
            res.status(401).send('Invalid Username or Password');
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

// --- PAGE NAVIGATION ---

// Public Pages
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));

// Protected Staff Pages
app.get('/dashboard', (req, res) => {
    if (req.session.isLoggedIn) res.sendFile(path.join(__dirname, 'dashboard.html'));
    else res.redirect('/login');
});

app.get('/documents', (req, res) => {
    if (req.session.isLoggedIn) res.sendFile(path.join(__dirname, 'documents.html'));
    else res.redirect('/login');
});

app.get('/settings', (req, res) => {
    if (req.session.isLoggedIn) res.sendFile(path.join(__dirname, 'settings.html'));
    else res.redirect('/login');
});

app.get('/admin', (req, res) => {
    if (req.session.isLoggedIn) res.sendFile(path.join(__dirname, 'admin.html'));
    else res.redirect('/login');
});

// Wildcard Fallback
app.get('*', (req, res) => res.redirect('/'));

// --- START SERVER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MSRP Portal Live on Port ${PORT}`));
