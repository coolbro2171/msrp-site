const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const otplib = require('otplib');
const qrcode = require('qrcode');

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
    
    // Badge Flags
    isDeveloper: { type: Boolean, default: false },
    isStaffInstructor: { type: Boolean, default: false },
    isDatabaseAccess: { type: Boolean, default: false },

    // Security
    twoFactorSecret: { type: String, default: null },
    twoFactorEnabled: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

// --- MIDDLEWARE ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(session({
    secret: 'msrp-secure-v11-final-build',
    resave: true,               // Forces session to be saved back to the store
    saveUninitialized: false,   // Don't create empty sessions
    store: MongoStore.create({ 
        mongoUrl: MONGODB_URI,
        touchAfter: 24 * 3600   // Only update the session once every 24 hours (saves database speed)
    }),
    cookie: { 
        secure: false,          // Keep false for Render.com unless you have a custom SSL setup
        httpOnly: true, 
        maxAge: 1000 * 60 * 60 * 24 // 1 Day
    }
}));

// --- RANK HIERARCHY ---
const ranks = ['User', 'Staff', 'Admin', 'Management', 'Owner'];

// --- API ENDPOINTS ---

// Fetch current user session data
app.get('/api/user-info', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).json({ error: "Unauthorized" });
    try {
        const user = await User.findOne({ username: req.session.username }, '-password');
        res.json(user);
    } catch (err) { res.status(500).json({ error: "Server Error" }); }
});

// Admin API: Fetch all users
app.get('/api/admin/users', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).json({ error: "Unauthorized" });
    const adminUser = await User.findOne({ username: req.session.username });
    if (!['Admin', 'Management', 'Owner'].includes(adminUser.role)) return res.status(403).json({ error: "Forbidden" });

    try {
        const users = await User.find({}, '-password');
        res.json(users);
    } catch (err) { res.status(500).json({ error: "Server Error" }); }
});

// Admin API: Promote/Demote logic
app.post('/api/admin/change-rank', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).json({ error: "Unauthorized" });
    const adminUser = await User.findOne({ username: req.session.username });
    if (!['Admin', 'Management', 'Owner'].includes(adminUser.role)) return res.status(403).json({ error: "Forbidden" });

    const { targetUsername, action } = req.body;
    try {
        const targetUser = await User.findOne({ username: targetUsername });
        if (!targetUser) return res.status(404).send("User not found");
        if (targetUser.role === 'Owner') return res.status(403).send("Cannot modify Owner");

        let currentIdx = ranks.indexOf(targetUser.role);
        let newIdx = action === 'promote' ? currentIdx + 1 : currentIdx - 1;

        if (newIdx < 0 || newIdx >= ranks.length) return res.status(400).send("Invalid rank limit");

        targetUser.role = ranks[newIdx];
        await targetUser.save();
        res.json({ success: true, newRole: targetUser.role });
    } catch (err) { res.status(500).send("Update failed"); }
});

// Admin API: Ban Toggle
app.post('/api/admin/toggle-ban', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).json({ error: "Unauthorized" });
    const adminUser = await User.findOne({ username: req.session.username });
    if (!['Admin', 'Management', 'Owner'].includes(adminUser.role)) return res.status(403).json({ error: "Forbidden" });

    const { targetUsername, isBanned } = req.body;
    try {
        const targetUser = await User.findOne({ username: targetUsername });
        if (targetUser.role === 'Owner') return res.status(403).send("Cannot ban Owner");

        targetUser.isBanned = isBanned;
        await targetUser.save();
        res.json({ success: true });
    } catch (err) { res.status(500).send("Ban update failed"); }
});

// --- 2FA LOGIC ---

app.get('/api/2fa/setup', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).send("Unauthorized");
    const user = await User.findOne({ username: req.session.username });
    const secret = otplib.authenticator.generateSecret();
    const otpauth = otplib.authenticator.keyuri(user.username, 'MSRP Portal', secret);
    
    user.twoFactorSecret = secret;
    await user.save();

    const qrImageUrl = await qrcode.toDataURL(otpauth);
    res.json({ qrImageUrl, secret });
});

app.post('/api/2fa/verify', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).send("Unauthorized");
    const { token } = req.body;
    const user = await User.findOne({ username: req.session.username });
    const isValid = otplib.authenticator.check(token, user.twoFactorSecret);

    if (isValid) {
        user.twoFactorEnabled = true;
        await user.save();
        res.json({ success: true });
    } else {
        res.status(400).json({ success: false });
    }
});

app.post('/api/2fa/disable', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).send("Unauthorized");
    try {
        await User.findOneAndUpdate({ username: req.session.username }, { twoFactorEnabled: false, twoFactorSecret: null });
        res.json({ success: true });
    } catch (err) { res.status(500).send("Disable failed"); }
});

// --- AUTHENTICATION ---

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.redirect('/login');
    } catch (err) { res.status(400).send("Registration failed. Username taken?"); }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (user && await bcrypt.compare(password, user.password)) {
            if (user.isBanned) return res.status(403).send('Account is banned.');
            
            // Set session data
            req.session.username = user.username;
            req.session.isLoggedIn = true;

            // IMPORTANT: Save the session BEFORE redirecting
            req.session.save((err) => {
                if (err) return res.status(500).send("Session Save Error");
                res.redirect('/dashboard');
            });
        } else {
            res.status(401).send('Invalid login details.');
        }
    } catch (err) { res.status(500).send("Server Error"); }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.clearCookie('connect.sid');
    res.redirect('/');
});

// --- PAGE ROUTING ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));

app.get('/dashboard', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, 'dashboard.html')) : res.redirect('/login'));
app.get('/settings', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, 'settings.html')) : res.redirect('/login'));
app.get('/admin', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, 'admin.html')) : res.redirect('/login'));
app.get('/documents', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, 'documents.html')) : res.redirect('/login'));

// Lowercase 2FA route
app.get('/2fa', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, '2fa-verify.html')) : res.redirect('/login'));

app.get('*', (req, res) => res.redirect('/'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MSRP Server running on port ${PORT}`));







