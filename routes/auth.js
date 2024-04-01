const router = require('express').Router()
const { check, validationResult } = require("express-validator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { users } = require('../database');

require('dotenv').config()
let refreshTokens = [];
router.get('/users', (req,res)=>{
    res.send(users)
})

router.post('/signup', async(req,res)=>{
    const { email, password } = req.body 
    let user = users.find(user=>{
        return user.email === email
    })
    if (user) return res.status(200).json({
        errors: [
            {
            email: user.email,
            msg: "The user already exists",
            },
        ],
    })
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)
    users.push({email: email, password: hashedPassword})
    const accessToken = jwt.sign({email}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '10s'})

    res.json({
        accessToken,
    });
})

router.post('/login', async (req,res)=>{
    const { email, password } = req.body 
    let user = users.find(user=>{
        return user.email === email
    })
    if(!user) return res.status(400).json({
        errors: [
            {
            email: email,
            msg: `User with email does not exist`,
            },
        ],
    })
    let isMatch = await bcrypt.compare(password,user.password)
    if (!isMatch) {
        return res.status(401).json({
            errors: [
            {
                msg: "Email or password is invalid",
            }
        ]})
    }
    const accessToken = await jwt.sign({email}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '10s'})
    const refreshToken = await jwt.sign({ email },process.env.REFRESH_TOKEN_SECRET, {expiresIn: "1m" });
    
    refreshTokens.push(refreshToken);
    res.json({
        accessToken,
        refreshToken
    }); 

    })

router.post("/token", async (req, res) => {
    const refreshToken = req.headers["authorization"] && req.headers["authorization"].split(' ')[1]
    
    // If token is not provided, send error message
    if (!refreshToken) {
        res.status(401).json({
            errors: [{ msg: "Token not found"}]
        });
    }
    
    // If token does not exist, send error message
    if (!refreshTokens.includes(refreshToken)) {
        res.status(403).json({
        errors: [{ msg: "Invalid refresh token"}]
        });
    }
    
    try {
        const user = await jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const { email } = user;
        const accessToken = await jwt.sign({ email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "10s" });
        res.json({ accessToken });
    } catch (error) {
        res.status(403).json({
        errors: [{ msg: "Invalid token"}],
        });
    }
    });

router.delete("/logout", (req, res) => {
        const refreshToken = req.header("x-auth-token");

        refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
        res.sendStatus(204);
});


module.exports = router;