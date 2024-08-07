const mongoose = require('mongoose')

const todoSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true
    },
    content: {
        type: String,
        required: true,
    },
    user: {
        type: mongoose.SchemaTypes.ObjectId,
        ref: 'User'
    },
}, { timestamps: true });


const TodoModel = mongoose.model('Todo', todoSchema);

module.exports = TodoModel;

