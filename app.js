require("./database/database").connect()
const express = require("express")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const cookieParser = require("cookie-parser")
const User = require("./model/user")
const auth = require("./middleware/auth")


const app = express()
app.use(express.json())
app.use(cookieParser())

app.get("/", (req, res) => {
    res.send("<h1>Server is working...</h1>")
})

app.post("/register", async (req, res) => {
    try {
        // get all data from body
        const {firstname, lastname, email, password} = req.body
        // all the data should exists
        if ([firstname, lastname, email, password].some((data) => data.trim().length === 0)) {
            return res.status(400).json({msg: "All fields are mandatory"})
        }
        // check if user already exists

        const existingUser = await User.findOne({ email: email })
        if (existingUser) {
            return res.status(401).json({msg: "User already exists with this email"})
        }

        // encrypt the password
        const myEncPassword = await bcrypt.hash(password, 10)
        // save the user in DB
        const user = await User.create({
            firstname: firstname,
            lastname: lastname,
            email: email,
            password: myEncPassword
        })
        
        // generate a token for user and send it 
        const token = jwt.sign(
            {id:user._id,email:user.email},
            "SECRET", // process.env.jwtsecret
            {
                expiresIn: "2h"
            }
        )
        user.token = token
        user.password = undefined

        return res.status(201).json(user)
        
    } catch (error) {
        console.log(error)
    }
})

app.post("/login", async (req, res) => {
    try {
        // get all data from frontend
        const {email, password} = req.body
        // validation
        if ([email, password].some((data) => data.trim().length === 0)) {
            return res.status(400).json({msg:"email & password is mandatory"})
        }
        // find user in DB
        const user = await User.findOne({email})
        if (!user) {
            return res.status(404).json({msg:"user is does not exists"})
        }

        // match the password
        const isPasswordCorrect = await bcrypt.compare(password, user.password)
        if (!isPasswordCorrect) {
            return res.status(400).json({msg:"Password is wrong"})
        }
        // send a token
        const token = jwt.sign(
            {id: user._id},
            "SECRET", // process.env.jwtsecret
            {
                expiresIn: "2h"
            }
        )
        user.token = token
        user.password = undefined

        // cookie section
        const options = {
            expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
            httpOnly: true
        };

        return res.status(200).cookie("token", token, options).json({
            success: true,
            token,
            user
        })

    } catch (error) {
        console.log(error);
    }
})

app.get("/dashboard", auth, (req, res) => {
    console.log(req.user)
    res.send("Welcome to dashboard")
})

app.get("/settings", (req, res) => {
    res.send("Here are your user settings")
})

module.exports = app