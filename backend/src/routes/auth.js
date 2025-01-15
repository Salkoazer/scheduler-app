const express = require('express');
const router = express.Router();
const { getDb } = require('../db/connection');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

router.post('/authenticate', async (req, res) => {
    const { username, password } = req.body;
    console.log(`Authenticating user: ${username}`);
    const db = getDb();
    const user = await db.collection('credentials').findOne({ username });

    if (!user) {
        console.log('User not found');
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    console.log(`User found: ${user.username}`);
    console.log(`Stored password hash: ${user.password}`);

    const passwordMatch = await bcrypt.compare(password, user.password);
    console.log(`Password match: ${passwordMatch}`);

    if (passwordMatch) {
        const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        console.log('Authentication successful');
        res.json({ token });
    } else {
        console.log('Invalid credentials');
        res.status(401).json({ message: 'Invalid credentials' });
    }
});

module.exports = router;