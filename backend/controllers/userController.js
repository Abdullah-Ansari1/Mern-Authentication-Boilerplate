const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const asyncHandler = require('express-async-handler')
const User = require('../models/userModel')
const axios = require("axios");
// @desc    Register new user
// @route   POST /api/users
// @access  Public
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body

  if (!name || !email || !password) {
    res.status(400)
    throw new Error('Please add all fields')
  }

  // Check if user exists
  const userExists = await User.findOne({ email })

  if (userExists) {
    res.status(400)
    throw new Error('User already exists')
  }

  // Hash password
  const salt = await bcrypt.genSalt(10)
  const hashedPassword = await bcrypt.hash(password, salt)

  // Create user
  const user = await User.create({
    name,
    email,
    password: hashedPassword,
  })

  if (user) {
    res.status(201).json({
      _id: user.id,
      name: user.name,
      email: user.email,
      token: generateToken(user._id),
    })
  } else {
    res.status(400)
    throw new Error('Invalid user data')
  }
})

// @desc    Authenticate a user
// @route   POST /api/users/login
// @access  Public
const loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body

  // Check for user email
  const user = await User.findOne({ email })

  if (user && (await bcrypt.compare(password, user.password))) {
    res.json({
      _id: user.id,
      name: user.name,
      email: user.email,
      token: generateToken(user._id),
    })
  } else {
    res.status(400)
    throw new Error('Invalid credentials')
  }
})


const signinWithGoogle = asyncHandler(async (req, res) => {
  const { access_token } = req.body;
  try {
    // let {data} = await axios.get(`https://oauth2.googleapis.com/tokeninfo?id_token=${access_token}`);
    let {data} = await axios.get(`https://www.googleapis.com/oauth2/v1/userinfo?access_token=${access_token}`);
    // let {data} = await axios.get(`https://www.googleapis.com/oauth2/v3/userinfo`,{
    //   headers: {
    //     'Authorization': `Bearer ${access_token}` 
    //   }
    // });
    if (data) {  
      const { email,name } = data;
      // Validate the user's identity
        const oldUser = await User.findOne({ email });
        //if not old user we create a new user
        if (!oldUser) {
          const salt = await bcrypt.genSalt(12);
    
          const hashedPassword = await bcrypt.hash("anypasswordyouwanttohashedwithsalt", salt);
    
          const result = await User.create({ email, password: hashedPassword, name});
          
          const token = generateToken(result._id);
    
          res.status(201).json({ result, token });
    
        }
         else if (oldUser) {//if old user
    
          const token = generateToken(oldUser._id);
          
          res.status(200).json({ result: oldUser, token });
        }
    }else{
      res.status(400)
      throw new Error('Invalid credentials')
    }
  } catch (error) {
    res.status(400)
    throw new Error('Invalid user data')
  // res.status(400).json(error.response.data);
  }
})

// @desc    Get user data
// @route   GET /api/users/me
// @access  Private
const getMe = asyncHandler(async (req, res) => {
  res.status(200).json(req.user)
})

// Generate JWT
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '30d',
  })
}

module.exports = {
  registerUser,
  loginUser,
  getMe,
  signinWithGoogle,
}
