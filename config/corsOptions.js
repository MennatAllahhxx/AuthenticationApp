const allowedOrigins = require('./allowedOrigins')

const corsOptions = {
    origin: (origin, callback) => {
        if (allowedOrigins.indexOf(origin) !== -1 || !origin) { //to check if the array is empty
            callback(null,  true);//no err
        } else {
            callback(new Error('Not allowed by CORS')); //DNS isnt in the allowed origins list
        }
    },
    credentials: true, //accept any data in the headers or the cookies
    optionsSuccessStatus: 200
};

module.exports = corsOptions;