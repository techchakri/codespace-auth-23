const jwt = require("jsonwebtoken")

const auth = (req, res, next) => {
    // grab token from cookie
    console.log(req.cookies)
    const {token} = req.cookies
    // if no token, stop there
    if (!token) {
        return res.status(403).send("Please login first")
    }
    // decode that token and get id
    try {
        const decode = jwt.verify(token, "SECRET")
        console.log(decode)
        // query to DB for that user id
        req.user = decode
        return next()
    } catch (error) {
        console.log(error)
        res.status(401).send("Invalid Token")
    }
}

module.exports = auth