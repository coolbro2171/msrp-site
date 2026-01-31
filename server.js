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

// --- SCHEMAS ---

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['User', 'Staff', 'Admin', 'Management', 'Owner'], default: 'User' },
    isBanned: { type: Boolean, default: false },
    isDeveloper: { type: Boolean, default: false },
    isStaffInstructor: { type: Boolean, default: false },
    isDatabaseAccess: { type: Boolean, default: false },
    twoFactorSecret: { type: String, default: null },
    twoFactorEnabled: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

// System Settings Schema (Banner)
const systemSchema = new mongoose.Schema({
    bannerText: { type: String, default: "Welcome to MSRP!" },
    isBannerActive: { type: Boolean, default: false }
});
const System = mongoose.model('System', systemSchema, 'system_settings');

// Blog Schema
const blogSchema = new mongoose.Schema({
    date: { type: String, required: true },
    title: { type: String, required: true },
    content: { type: String, required: true },
    order: { type: Number, default: 0 }
});
const Blog = mongoose.model('Blog', blogSchema, 'blog_updates');

// Audit Log Schema
const auditSchema = new mongoose.Schema({
    action: { type: String, required: true },
    performedBy: { type: String, required: true },
    targetUser: { type: String, required: true },
    details: { type: String },
    timestamp: { type: Date, default: Date.now }
});
const AuditLog = mongoose.model('AuditLog', auditSchema, 'audit_logs');

// --- MIDDLEWARE ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(session({
    secret: 'msrp-secure-v11-final-build',
    resave: true,               
    saveUninitialized: false,   
    store: MongoStore.create({ 
        mongoUrl: MONGODB_URI,
        touchAfter: 24 * 3600   
    }),
    cookie: { 
        secure: false,          
        httpOnly: true, 
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24 
    }
}));

const ranks = ['User', 'Staff', 'Admin', 'Management', 'Owner'];

// --- SYSTEM & BLOG API (PUBLIC) ---

app.get('/api/system/banner', async (req, res) => {
    try {
        const settings = await System.findOne();
        res.json(settings || { isBannerActive: false, bannerText: "" });
    } catch (err) {
        res.status(500).json({ error: "Database error" });
    }
});

app.get('/api/blog-updates', async (req, res) => {
    try {
        const updates = await Blog.find().sort({ order: -1 });
        res.json(updates);
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch blog updates" });
    }
});

// --- ADMIN API ENDPOINTS ---

app.get('/api/user-info', async (req, res) => {
    if (!req.session.isLoggedIn || !req.session.username) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    try {
        const user = await User.findOne({ username: req.session.username }, '-password');
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json(user);
    } catch (err) { res.status(500).json({ error: "Server Error" }); }
});

app.get('/api/admin/users', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).json({ error: "Unauthorized" });
    const adminUser = await User.findOne({ username: req.session.username });
    if (!adminUser || !['Admin', 'Management', 'Owner'].includes(adminUser.role)) return res.status(403).json({ error: "Forbidden" });

    try {
        const users = await User.find({}, '-password');
        res.json(users);
    } catch (err) { res.status(500).json({ error: "Server Error" }); }
});

app.post('/api/admin/change-rank', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).json({ error: "Unauthorized" });
    const adminUser = await User.findOne({ username: req.session.username });
    if (!adminUser || !['Admin', 'Management', 'Owner'].includes(adminUser.role)) return res.status(403).json({ error: "Forbidden" });

    const { targetUsername, action } = req.body;
    try {
        const targetUser = await User.findOne({ username: targetUsername });
        if (!targetUser) return res.status(404).send("User not found");
        if (targetUser.role === 'Owner') return res.status(403).send("Cannot modify Owner");

        const oldRole = targetUser.role;
        let currentIdx = ranks.indexOf(targetUser.role);
        let newIdx = action === 'promote' ? currentIdx + 1 : currentIdx - 1;

        if (newIdx < 0 || newIdx >= ranks.length) return res.status(400).send("Invalid rank limit");

        targetUser.role = ranks[newIdx];
        await targetUser.save();

        // Audit Logging
        const log = new AuditLog({
            action: "RANK_CHANGE",
            performedBy: req.session.username,
            targetUser: targetUsername,
            details: `Changed from ${oldRole} to ${targetUser.role}`
        });
        await log.save();

        res.json({ success: true, newRole: targetUser.role });
    } catch (err) { res.status(500).send("Update failed"); }
});

app.post('/api/admin/toggle-ban', async (req, res) => {
    if (!req.session.isLoggedIn) return res.status(401).json({ error: "Unauthorized" });
    const adminUser = await User.findOne({ username: req.session.username });
    if (!adminUser || !['Admin', 'Management', 'Owner'].includes(adminUser.role)) return res.status(403).json({ error: "Forbidden" });

    const { targetUsername, isBanned } = req.body;
    try {
        const targetUser = await User.findOne({ username: targetUsername });
        if (targetUser.role === 'Owner') return res.status(403).send("Cannot ban Owner");

        targetUser.isBanned = isBanned;
        await targetUser.save();

        // Audit Logging
        const log = new AuditLog({
            action: isBanned ? "BAN_USER" : "UNBAN_USER",
            performedBy: req.session.username,
            targetUser: targetUsername,
            details: isBanned ? "User was banned from portal" : "User was unbanned from portal"
        });
        await log.save();

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
            
            req.session.username = user.username;
            req.session.isLoggedIn = true;

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
app.get('/2fa', (req, res) => req.session.isLoggedIn ? res.sendFile(path.join(__dirname, '2fa-verify.html')) : res.redirect('/login'));

app.get('*', (req, res) => res.redirect('/'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`MSRP Server running on port ${PORT}`));




