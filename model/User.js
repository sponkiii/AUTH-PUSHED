const mongoose = require('mongoose');

// creating a scema which is an object that represents the model of our user
const userSchema = new mongoose.Schema({
    // here we define the properties we wanna have, which is also an object where we can define more properties
    name: {
        type: String,
        required: true,
        max: 255,
        min: 6
    },
    email:{
        type: String,
        required: true,
        max: 255,
        min: 6
    },
    password:{
        type: String,
        required: true,
        max: 1024,
        min: 6
    },
    date:{
        type: Date,
        default: Date.now
    },



});


// to enable to export
module.exports = mongoose.model('User',userSchema);
