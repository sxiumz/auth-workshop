import 'dotenv/config';
import express from 'express';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json());

const SECRET = process.env.JWT_SECRET;

const users = [
    { id: 1, email: "admin@example.com", password: "admin123", role: "admin" },
    { id: 2, email: "user@example.com", password: "user123", role: "user" }
];

// AUTH middleware
const auth = (req, res, next) => {
    const h = req.headers.authorization || "";
    const [type, token] = h.split(" ");

    if (type !== "Bearer" || !token) {
        return res.status(401).json({ error: "Missing token" });
    }

    try {
        req.user = jwt.verify(token, SECRET);
        next();
    } catch (e) {
        return res.status(401).json({ error: "Invalid or expired token" });
    }
};

// ROLE middleware
const role = (roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) {
        return res.status(403).json({ error: "Forbidden" });
    }
    next();
};

// LOGIN
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    const u = users.find(x => x.email === email && x.password === password);
    if (!u) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
        { sub: u.id, role: u.role },
        SECRET,
        { expiresIn: "15m" }
    );

    res.json({
        access_token: token,
        token_type: "Bearer",
        expires_in: 900
    });
});

// PROFILE (protected)
app.get("/profile", auth, (req, res) => {
    res.json({ user_id: req.user.sub, role: req.user.role });
});

// DELETE (admin only)
app.delete("/users/:id", auth, role(["admin"]), (req, res) => {
    res.json({ message: `User ${req.params.id} deleted (demo)` });
});

app.listen(process.env.PORT, () =>
    console.log(`Server running → http://localhost:${process.env.PORT}`)
);
