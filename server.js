require('./config/db');
const cors = require('cors');
const morgan = require("morgan");
const express = require('express');
const PORT = process.env.PORT || 1989;
const secret = process.env.JWT_SECRET 
const userRouter = require('./routers/userRouter');
const todoRouter = require('./routers/todoRouter');

const app = express();
app.use(cors({origin: "*"}));

app.use(morgan("dev"))
app.use(express.json());

app.use('/api', userRouter)
app.use('/api', todoRouter)


app.listen(PORT, () => {
    console.log(`Server is listening to PORT: ${PORT}`);
})