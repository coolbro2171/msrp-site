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
    .then(() => console.log("Database Connected Successfully"))
    .catch(err => console.error("Database connection error:", err));

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
    secret: 'secure-dev-key-789',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGODB_URI }),
    cookie: { maxAge: 3600000 }
}));

// --- API ROUTES ---
app.get('/api/users', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).send('Unauthorized');
    try {
        const users = await User.find({}, '-password');
        res.json(users);
    } catch (err) { res.status(500).send('Error loading users'); }
});

app.post('/api/promote-user/:username', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).send('Unauthorized');
    try {
        const target = await User.findOne({ username: req.params.username });
        if (target) {
            target.role = req.body.newRole;
            await target.save();
            res.sendStatus(200);
        } else { res.status(404).send('User not found'); }
    } catch (err) { res.status(500).send('Promotion failed'); }
});

// --- AUTH ROUTES ---
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        if (user.isBanned) return res.status(403).send('Account Banned');
        req.session.username = username;
        req.session.isLoggedIn = true;
        res.redirect('/dashboard');
    } else { res.status(401).send('Invalid Login'); }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// --- PAGE NAVIGATION ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/dashboard', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, 'dashboard.html')) : res.redirect('/'));
app.get('/admin', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, 'admin.html')) : res.redirect('/'));

app.listen(3000, () => console.log("MSRP Portal running on Port 3000"));
