const { publicPosts, privatePosts } = require('../database')
const authToken = require('../middleware/authToken')

const router = require('express').Router()
require('dotenv').config()

router.get('/public', (req,res)=>{
    res.send(publicPosts)
})
router.get('/private', authToken ,(req,res)=>{
    res.send(privatePosts)
})
module.exports = router