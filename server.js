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
    .then(() => console.log("MSRP Database Connected"))
    .catch(err => console.error("Database Connection Error:", err));

// --- USER SCHEMA ---
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['User', 'Staff', 'Admin', 'Management', 'Owner'], default: 'User' },
    isBanned: { type: Boolean, default: false },
    
    // Badge System
    isDeveloper: { type: Boolean, default: false },
    isStaffInstructor: { type: Boolean, default: false },
    hasDatabaseAccess: { type: Boolean, default: false },

    twoFactorSecret: { type: String, default: null },
    twoFactorEnabled: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

// --- MIDDLEWARE ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(session({
    secret: 'msrp-secure-v10-lowercase',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGODB_URI }),
    cookie: { secure: false, httpOnly: true, maxAge: 1000 * 60 * 60 * 24 }
}));

// --- API ENDPOINTS ---

app.get('/api/user-info', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).json({ error: "Unauthorized" });
    try {
        const user = await User.findOne({ username: req.session.username }, '-password');
        res.json(user);
    } catch (err) { res.status(500).json({ error: "Server Error" }); }
});

// Admin API: User Management
app.post('/api/admin/update-user', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).json({ error: "Unauthorized" });
    
    const adminUser = await User.findOne({ username: req.session.username });
    if (!['Admin', 'Management', 'Owner'].includes(adminUser.role)) return res.status(403).json({ error: "Forbidden" });

    const { targetUsername, role, isDeveloper, isStaffInstructor, hasDatabaseAccess, isBanned } = req.body;
    
    try {
        await User.findOneAndUpdate({ username: targetUsername }, {
            role,
            isDeveloper,
            isStaffInstructor,
            hasDatabaseAccess,
            isBanned
        });
        res.json({ message: "User updated successfully" });
    } catch (err) { res.status(500).json({ error: "Update failed" }); }
});

// --- AUTH LOGIC ---

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.redirect('/login');
    } catch (err) { res.status(400).send("Registration failed."); }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        if (user.isBanned) return res.status(403).send('Your account is banned.');
        req.session.username = user.username;
        req.session.isLoggedIn = true;
        req.session.save(() => res.redirect('/dashboard'));
    } else { res.status(401).send('Invalid login.'); }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.clearCookie('connect.sid');
    res.redirect('/');
});

// --- PAGE NAVIGATION ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));

app.get('/dashboard', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, 'dashboard.html')) : res.redirect('/login'));
app.get('/documents', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, 'documents.html')) : res.redirect('/login'));
app.get('/settings', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, 'settings.html')) : res.redirect('/login'));
app.get('/admin', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, 'admin.html')) : res.redirect('/login'));

// Updated Route: Pointing to the lowercase file
app.get('/2fa', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, '2fa-verify.html')) : res.redirect('/login'));

app.get('*', (req, res) => res.redirect('/'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MSRP Portal Live | Lowercase Routing Active`));


