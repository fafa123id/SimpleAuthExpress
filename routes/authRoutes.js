const express = require('express');
const { registerUser, loginUser, getUser } = require('../controllers/authcontroller');
const { verifyToken } = require('../middleware/authMiddleware');

const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.get('/user', verifyToken, getUser);
module.exports = router;
