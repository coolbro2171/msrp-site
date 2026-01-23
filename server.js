const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');

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
    role: { type: String, enum: ['User', 'Staff', 'Admin', 'Management', 'Owner'], default: 'User' },
    isBanned: { type: Boolean, default: false },
    twoFactorSecret: { type: String },
    twoFactorEnabled: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

// --- MIDDLEWARE ---
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(__dirname)); 
app.use('/files', express.static(path.join(__dirname, 'files'))); 

app.use(session({
    secret: 'secure-dev-key-789',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGODB_URI }),
    cookie: { maxAge: 3600000, sameSite: 'lax', secure: false }
}));

// --- KEEP-ALIVE ROUTE ---
app.get('/ping', (req, res) => res.status(200).send('Server is awake'));

const protect = (req, res, next) => {
    if (req.session.isLoggedIn && !req.session.needs2FA) {
        next();
    } else if (req.session.needs2FA) {
        res.redirect('/2fa-verify');
    } else {
        res.redirect('/');
    }
};

// --- PAGE ROUTES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/dashboard', protect, (req, res) => res.sendFile(path.join(__dirname, 'dashboard.html')));
app.get('/settings', protect, (req, res) => res.sendFile(path.join(__dirname, 'settings.html')));
app.get('/documents', protect, (req, res) => res.sendFile(path.join(__dirname, 'documents.html')));

app.get('/2fa-verify', (req, res) => {
    if (!req.session.username || !req.session.needs2FA) return res.redirect('/');
    res.sendFile(path.join(__dirname, '2fa-verify.html'));
});

app.get('/admin', protect, async (req, res) => {
    const user = await User.findOne({ username: req.session.username });
    const hasAccess = user && ['Owner', 'Management', 'Admin'].includes(user.role);
    if (hasAccess) {
        res.sendFile(path.join(__dirname, 'admin.html'));
    } else {
        res.status(403).send('Unauthorized access. Admin+ required.');
    }
});

// --- API ROUTES (Staff Management) ---

app.get('/api/me', protect, async (req, res) => {
    const user = await User.findOne({ username: req.session.username });
    res.json({ 
        username: user.username, 
        role: user.role, 
        twoFactorEnabled: user.twoFactorEnabled 
    });
});

app.get('/api/users', protect, async (req, res) => {
    const users = await User.find({}, 'username role isBanned');
    res.json(users);
});

// FIXED BAN/UNBAN ROUTE
app.post('/api/ban-user/:username', protect, async (req, res) => {
    const currentUser = await User.findOne({ username: req.session.username });
    if (!['Owner', 'Management', 'Admin'].includes(currentUser.role)) return res.sendStatus(403);
    
    const target = await User.findOne({ username: req.params.username });
    if (!target) return res.status(404).send('User not found');
    if (target.role === 'Owner') return res.status(403).send('Cannot ban an Owner');

    target.isBanned = req.body.isBanned;
    await target.save();
    res.sendStatus(200);
});

// FIXED DELETE USER ROUTE
app.delete('/api/delete-user/:username', protect, async (req, res) => {
    const currentUser = await User.findOne({ username: req.session.username });
    if (!['Owner', 'Management'].includes(currentUser.role)) return res.sendStatus(403);
    
    const target = await User.findOne({ username: req.params.username });
    if (target && target.role === 'Owner') return res.status(403).send('Cannot delete an Owner');

    const result = await User.deleteOne({ username: req.params.username });
    if (result.deletedCount === 1) res.sendStatus(200);
    else res.status(404).send('User not found');
});

app.post('/api/promote-user/:username', protect, async (req, res) => {
    const currentUser = await User.findOne({ username: req.session.username });
    const target = await User.findOne({ username: req.params.username });
    const { newRole } = req.body; 

    if (!target) return res.status(404).send('User not found');
    if (target.role === 'Owner') return res.status(403).send('Cannot modify Owner');

    const isOwnerOrMgt = ['Owner', 'Management'].includes(currentUser.role);
    const isAdminPromotingToStaff = currentUser.role === 'Admin' && target.role === 'User' && newRole === 'Staff';
    const isAdminDemotingStaff = currentUser.role === 'Admin' && target.role === 'Staff' && newRole === 'User';

    if (isOwnerOrMgt || isAdminPromotingToStaff || isAdminDemotingStaff) {
        target.role = newRole;
        await target.save();
        return res.sendStatus(200);
    }
    res.status(403).send('Unauthorized rank change.');
});

// --- 2FA & SETTINGS API ---
app.post('/api/settings/2fa/setup', protect, async (req, res) => {
    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(req.session.username, 'MSRP-Portal', secret);
    const user = await User.findOne({ username: req.session.username });
    user.twoFactorSecret = secret; 
    await user.save();
    const qrImageUrl = await qrcode.toDataURL(otpauth);
    res.json({ qrCode: qrImageUrl });
});

app.post('/api/settings/2fa/verify', protect, async (req, res) => {
    const { token } = req.body;
    const user = await User.findOne({ username: req.session.username });
    if (authenticator.check(token, user.twoFactorSecret)) {
        user.twoFactorEnabled = true;
        await user.save();
        res.sendStatus(200);
    } else {
        res.status(400).send("Invalid code.");
    }
});

app.post('/api/settings/2fa/disable', protect, async (req, res) => {
    const user = await User.findOne({ username: req.session.username });
    user.twoFactorEnabled = false;
    user.twoFactorSecret = null;
    await user.save();
    res.send("2FA Disabled.");
});

// --- LOGIN & AUTH ---
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
    
    // Safety check for Banned Users
    if (user && user.isBanned) {
        return res.status(403).send('This account is currently banned.');
    }

    if (user && await bcrypt.compare(password, user.password)) {
        req.session.username = username;
        req.session.role = user.role;
        if (user.twoFactorEnabled) {
            req.session.needs2FA = true;
            return res.redirect('/2fa-verify');
        }
        req.session.isLoggedIn = true;
        res.redirect('/dashboard');
    } else {
        res.status(401).send('Invalid credentials.');
    }
});

app.post('/api/login/2fa-verify', async (req, res) => {
    const { token } = req.body;
    const user = await User.findOne({ username: req.session.username });
    if (authenticator.check(token, user.twoFactorSecret)) {
        req.session.isLoggedIn = true;
        delete req.session.needs2FA;
        res.sendStatus(200);
    } else {
        res.status(400).send("Invalid code.");
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.listen(process.env.PORT || 3000, () => console.log("Server Live"));
