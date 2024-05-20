require("dotenv").config();
const express = require("express");
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');

const cookieParser = require('cookie-parser');
const connectDB = require('./config/dbConn');
const corsOptions = require('./config/corsOptions');

const app = express();
const PORT = process.env.PORT || 5000;

//connect to db
connectDB();

//to specify cors options like DNS reaching my server, credentials and so on
app.use(cors(corsOptions));

//allow server to parse cookies
app.use(cookieParser());

//to use JSON
app.use(express.json());

//get style page for root page
app.use('/', express.static(path.join(__dirname, "public")));

//get root page
app.get('/', require('./routes/root'));

//auth routes
app.use('/auth', require('./routes/authRoutes'));

//get all users
app.use('/users', require('./routes/userRoutes'));

//for unknown paths
app.all('*', (req, res) => {
    res.status(404);
    if (req.accepts('html')) {
        res.sendFile(path.join(__dirname, 'views', '404.html'))
    } else if (req.accepts('json')) {
        res.json({message: '404 Not Found'})
    } else {
        res.type('txt').send('404 Not Found');
    }
});

//once connected to db, connect to the server
mongoose.connection.once("open", () => {
    console.log('connected to the mongodb');

    app.listen(PORT, () => {
        console.log('server running on port ', PORT);
    }); 
});

//if there's an error with connecting to the db
mongoose.connection.on('error', (err) => {
    console.log(err);
})