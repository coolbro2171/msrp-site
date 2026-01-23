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
app.get('/2fa-verify', (req, res) => {
    if (!req.session.username || !req.session.needs2FA) return res.redirect('/');
    res.sendFile(path.join(__dirname, '2fa-verify.html'));
});

app.get('/documents', protect, async (req, res) => {
    const user = await User.findOne({ username: req.session.username });
    if (user && user.role !== 'User') {
        res.sendFile(path.join(__dirname, 'documents.html'));
    } else {
        res.status(403).send('Unauthorized. Staff+ access required.');
    }
});

app.get('/admin', protect, async (req, res) => {
    const user = await User.findOne({ username: req.session.username });
    const hasAccess = user && ['Owner', 'Management', 'Admin'].includes(user.role);
    if (hasAccess) {
        res.sendFile(path.join(__dirname, 'admin.html'));
    } else {
        res.status(403).send('Unauthorized access.');
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// --- SETTINGS & SECURITY API ---

app.post('/api/settings/password', protect, async (req, res) => {
    const { oldPass, newPass } = req.body;
    const user = await User.findOne({ username: req.session.username });
    if (user && await bcrypt.compare(oldPass, user.password)) {
        user.password = await bcrypt.hash(newPass, 10);
        await user.save();
        res.send("Password updated successfully.");
    } else {
        res.status(400).send("Incorrect current password.");
    }
});

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
    const isValid = authenticator.check(token, user.twoFactorSecret);
    if (isValid) {
        user.twoFactorEnabled = true;
        await user.save();
        res.sendStatus(200);
    } else {
        res.status(400).send("Invalid token.");
    }
});

app.delete('/api/settings/account', protect, async (req, res) => {
    await User.findOneAndDelete({ username: req.session.username });
    req.session.destroy();
    res.sendStatus(200);
});

// --- MANAGEMENT API ---

app.post('/api/promote-user/:username', protect, async (req, res) => {
    try {
        const currentUser = await User.findOne({ username: req.session.username });
        const target = await User.findOne({ username: req.params.username });
        if (!target) return res.status(404).send('User not found');

        if (target.role === 'User' && (['Owner', 'Management', 'Admin'].includes(currentUser.role))) {
            target.role = 'Staff';
        } else if (target.role === 'Staff' && (['Owner', 'Management'].includes(currentUser.role))) {
            target.role = 'Admin';
        } else if (target.role === 'Admin' && currentUser.role === 'Owner') {
            target.role = 'Management';
        } else {
            return res.status(403).send('Unauthorized promotion.');
        }
        await target.save();
        res.sendStatus(200);
    } catch (err) { res.status(500).send('Error'); }
});

app.post('/api/demote-user/:username', protect, async (req, res) => {
    try {
        const currentUser = await User.findOne({ username: req.session.username });
        const target = await User.findOne({ username: req.params.username });
        if (!target) return res.status(404).send('User not found');

        if (target.role === 'Staff' && (['Owner', 'Management', 'Admin'].includes(currentUser.role))) {
            target.role = 'User';
        } else if (target.role === 'Admin' && (['Owner', 'Management'].includes(currentUser.role))) {
            target.role = 'Staff';
        } else if (target.role === 'Management' && currentUser.role === 'Owner') {
            target.role = 'Admin';
        } else {
            return res.status(403).send('Unauthorized demotion.');
        }
        await target.save();
        res.sendStatus(200);
    } catch (err) { res.status(500).send('Error'); }
});

app.post('/api/ban-user/:username', protect, async (req, res) => {
    try {
        const currentUser = await User.findOne({ username: req.session.username });
        const target = await User.findOne({ username: req.params.username });
        if (!target || target.role === 'Owner') return res.sendStatus(403);
        const canBan = currentUser.role === 'Owner' || currentUser.role === 'Management' || (currentUser.role === 'Admin' && (target.role === 'User' || target.role === 'Staff'));
        if (canBan) {
            target.isBanned = !target.isBanned;
            await target.save();
            res.sendStatus(200);
        } else { res.sendStatus(403); }
    } catch (err) { res.status(500).send('Error'); }
});

app.delete('/api/delete-user/:username', protect, async (req, res) => {
    try {
        const currentUser = await User.findOne({ username: req.session.username });
        const target = await User.findOne({ username: req.params.username });
        if (!target || target.role === 'Owner') return res.sendStatus(403);
        const canDelete = currentUser.role === 'Owner' || currentUser.role === 'Management' || (currentUser.role === 'Admin' && (target.role === 'User' || target.role === 'Staff'));
        if (canDelete) {
            await User.findOneAndDelete({ username: req.params.username });
            res.sendStatus(200);
        } else { res.sendStatus(403); }
    } catch (err) { res.status(500).send('Error'); }
});

// --- AUTHENTICATION & 2FA ---

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
    if (!user) return res.status(404).send("User not found");
    const isValid = authenticator.check(token, user.twoFactorSecret);
    if (isValid) {
        req.session.isLoggedIn = true;
        delete req.session.needs2FA;
        res.sendStatus(200);
    } else {
        res.status(400).send("Invalid token");
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
