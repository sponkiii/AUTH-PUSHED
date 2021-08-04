const express = require('express');
const app = new express();
const dotenv = require('dotenv');
const mongoose = require('mongoose');
// import routes
const authRoute = require('./routes/auth');
const postRoute = require('./routes/posts');
//const { request } = require('express');


// for dotenv to work
dotenv.config();


// connect to DB
mongoose.connect(process.env.DB_CONNECT, { useNewUrlParser: true, useUnifiedTopology: true  }, () => 
    console.log('connected to db!')
);

// Middlewear to send post requests
app.use(express.json());

// Route Middleweares
app.use('/api/user', authRoute);
app.use('/api/posts', postRoute);


// now lets make a port
app.listen(3000, () => console.log('Server Up and Running'));






//shift + tab to un-tab