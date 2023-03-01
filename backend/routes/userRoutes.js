const express = require('express')
const router = express.Router()
const {
  registerUser,
  loginUser,
  getMe,
  signinWithGoogle,
} = require('../controllers/userController')
const { protect } = require('../middleware/authMiddleware')

router.post('/register', registerUser)
router.post('/login', loginUser)
router.post('/signinwithgoogle',signinWithGoogle)
router.get('/me', protect, getMe)

module.exports = router
