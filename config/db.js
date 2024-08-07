require('dotenv').config();
const mongoose = require('mongoose');
const URL = process.env.DATABASE
mongoose.connect(URL)
.then(() => {
    console.log('Database connected successfully');
})
.catch((e) => {
    console.log('Database failed to connect: ', e.message);
})