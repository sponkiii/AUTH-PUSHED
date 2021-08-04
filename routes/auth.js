const router = require('express').Router();
const User = require('../model/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { registerValidation, loginValidation } = require('../validation');



// creating our empty router here
router.post('/register', async (req, res) => {

    // Validation DATA before we make a user
    const { error } = registerValidation(req.body);
    if(error) return res.status(400).send(error.details[0].message);

    //Checking if user is already in the database
    const emailExist = await User.findOne({email: req.body.email});
    if(emailExist) return res.status(400).send('Email already exists');

    //HASH the PASSWORD
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    //Create New User
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,

    });
    try{
        // here we try to save user
        const savedUser = await user.save();
        res.send({user: user._id});
    }catch(err){
        // incase we catch an err we respond with this
        res.status(400).send(err);
    }
});

//LOGIN
router.post('/login', async (req, res) => {
    // Validation email and password
    const { error } = loginValidation(req.body);
    if(error) return res.status(400).send(error.details[0].message);

        //Checking if user exist
        const user = await User.findOne({email: req.body.email});
        if(!user) return res.status(400).send('Email is not found!');

        //Check if Password is correct
        const validPass = await bcrypt.compare(req.body.password, user.password);
        if(!validPass) return res.status(400).send('Invalid Password!');

        // Create and assign a token
        const token = jwt.sign({_id: user._id}, process.env.TOKEN_SECRET);
        res.header('auth-token', token).send(token);

});


// to export this on other files
module.exports = router;