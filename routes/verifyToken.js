const jwt = require('jsonwebtoken');

module.exports = function(req, res, next){
    // gets value of auth-token from header
    const token = req.header('auth-token');
    // Check if has no token we send 401 stat with access denied
    if(!token) return res.status(401).send('Access Denied!');

    //If Token is available we'll verify token
    try{
        // Verifying token with our tokensecret we made
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        //If verified it throws back the ID of user
        req.user = verified;
        next();
        
    }catch(err){
        //If not verified, we send and invalid token msg
        res.status(400).send('Invalid Token!');
    }


};