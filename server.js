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
    .then(() => console.log("Connected to Database Successfully"))
    .catch(err => console.error("Database connection error:", err));

// --- USER SCHEMA ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['User', 'Staff', 'Admin', 'Owner'], default: 'User' },
    isBanned: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

// --- MIDDLEWARE ---
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(__dirname));

app.use(session({
    secret: 'secure-dev-key-789',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGODB_URI }),
    cookie: { maxAge: 3600000, sameSite: 'lax', secure: false }
}));

const protect = (req, res, next) => {
    if (req.session.isLoggedIn) next();
    else res.redirect('/');
};

// --- PAGE ROUTES ---

// Main Login Page
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Fix for "Cannot GET /register"
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));

// Dashboard (Pending screen for Users, Documents link for Staff+)
app.get('/dashboard', protect, (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));

// Fix for "Not Found /documents"
app.get('/documents', protect, async (req, res) => {
    const user = await User.findOne({ username: req.session.username });
    if (user && user.role !== 'User') {
        res.sendFile(path.join(__dirname, 'documents.html'));
    } else {
        res.status(403).send('Unauthorized. Staff+ access required.');
    }
});

// Admin Panel (Admin/Owner Only)
app.get('/admin', protect, async (req, res) => {
    const user = await User.findOne({ username: req.session.username });
    if (user && (user.role === 'Admin' || user.role === 'Owner')) {
        res.sendFile(path.join(__dirname, 'admin.html'));
    } else {
        res.status(403).send('Unauthorized access. Admins only.');
    }
});

// Logout Fix
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// --- MANAGEMENT API (PROMOTION PIPELINE) ---

// Path: User -> Staff -> Admin
app.post('/api/promote-user/:username', protect, async (req, res) => {
    try {
        const currentUser = await User.findOne({ username: req.session.username });
        const target = await User.findOne({ username: req.params.username });

        if (!target) return res.status(404).send('User not found');

        // Step 1: User to Staff (Admins and Owners can do this)
        if (target.role === 'User' && (currentUser.role === 'Owner' || currentUser.role === 'Admin')) {
            await User.findOneAndUpdate({ username: req.params.username }, { role: 'Staff' });
            res.sendStatus(200);
        } 
        // Step 2: Staff to Admin (Only the Owner can do this)
        else if (target.role === 'Staff' && currentUser.role === 'Owner') {
            await User.findOneAndUpdate({ username: req.params.username }, { role: 'Admin' });
            res.sendStatus(200);
        } else {
            res.status(403).send('Invalid promotion path.');
        }
    } catch (err) { res.status(500).send('Error'); }
});

app.post('/api/demote-user/:username', protect, async (req, res) => {
    if (req.session.role !== 'Owner') return res.sendStatus(403);
    try {
        const target = await User.findOne({ username: req.params.username });
        const newRole = target.role === 'Admin' ? 'Staff' : 'User';
        await User.findOneAndUpdate({ username: req.params.username }, { role: newRole });
        res.sendStatus(200);
    } catch (err) { res.status(500).send('Error'); }
});

app.post('/api/ban-user/:username', protect, async (req, res) => {
    try {
        const currentUser = await User.findOne({ username: req.session.username });
        const target = await User.findOne({ username: req.params.username });
        if (!target || target.role === 'Owner') return res.sendStatus(403);

        const canBan = currentUser.role === 'Owner' || 
                      (currentUser.role === 'Admin' && (target.role === 'User' || target.role === 'Staff'));

        if (canBan) {
            target.isBanned = !target.isBanned;
            await target.save();
            res.sendStatus(200);
        } else { res.sendStatus(403); }
    } catch (err) { res.status(500).send('Error'); }
});

// --- AUTHENTICATION ---

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const count = await User.countDocuments();
        const role = count === 0 ? 'Owner' : 'User';
        await new User({ username, password: hashedPassword, role }).save();
        res.redirect('/');
    } catch (err) { res.status(500).send('Registration failed.'); }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (user && await bcrypt.compare(password, user.password)) {
        if (user.isBanned) return res.status(403).send('Your account is banned.');
        
        req.session.isLoggedIn = true;
        req.session.username = username;
        req.session.role = user.role;
        
        // REDIRECT FIX: Send Staff to Dashboard, Admins/Owner to Admin Panel
        if (user.role === 'Admin' || user.role === 'Owner') {
            res.redirect('/admin');
        } else {
            res.redirect('/dashboard');
        }
    } else {
        res.status(401).send('Invalid credentials.');
    }
});

app.get('/api/users', protect, async (req, res) => {
    const users = await User.find({}, 'username role isBanned');
    res.json(users);
});

app.get('/api/me', protect, (req, res) => {
    res.json({ username: req.session.username, role: req.session.role });
});

app.listen(process.env.PORT || 3000, () => console.log("Server Live"));
