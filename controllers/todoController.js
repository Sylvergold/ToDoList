const TodoModel = require('../models/todoModel');
const UserModel = require('../models/userModel');

exports.createContent = async (req, res) => {
    try {
        const { userId } = req.user;
        const { title, content } = req.body;
        const user = await UserModel.findById(userId);
        if (!user) {
            return res.status(404).json({
                message: 'User not found'
            })
        }
        // Create an Instance of the content
        const todo = new TodoModel({
            title,
            content
        })

        todo.user = userId;
        user.todo.push(todo._id);

        // Save the documents too the database
        await todo.save();
        await user.save();

        // Send a success response
        res.status(201).json({
            message: "Todo content created successfully",
            data: todo
        });

    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.getOneContent = async (req, res) => {
    try {
        const { todoId } = req.params;
        const todo = await TodoModel.findById(todoId);
        if (!todo) {
            return res.status(404).json({
                message: 'Todo Content Not Found'
            })
        }
        res.status(200).json({
            message: 'Content retrieved successfully',
            data: todo
        })
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.getAllContent = async (req, res) => {
    try {
        const { userId } = req.user;
        const contents = await TodoModel.find({ user: userId });
        res.status(200).json({
            message: 'All contents found',
            data: contents
        })
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.updateContent = async (req, res) => {
    try {
        const { userId } = req.user;
        const { todoId } = req.params;
        const { title, content } = req.body;
        const user = await UserModel.findById(userId);
        if (!user) {
            return res.status(404).json({
                message: 'User not found'
            })
        }
        const todo = await TodoModel.findById(todoId);
        if (!todo) {
            return res.status(404).json({
                message: 'Todo Content Not Found'
            })
        }

        if(todo.user.toString() !== userId.toString()){
            return res.status(401).json({
                message: 'Not allowed to update a content by another user.'
            })
        }

        const data = {
            title: title || todo.title,
            content: content || todo.content
        }

        const updatedContent = await TodoModel.findByIdAndUpdate(todoId, data, { new: true });
        res.status(200).json({
            message: 'Content updated successfully',
            data: updatedContent
        })
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.deleteContent = async (req, res) => {
    try {
        const { todoId } = req.params;
        const todo = await TodoModel.findById(todoId);
        if (!todo) {
            return res.status(404).json({
                message: 'Todo Content Not Found'
            })
        }
        const deletedContent = await TodoModel.findByIdAndDelete(todoId);
        res.status(200).json({
            message: 'Content deleted successfully'
        })
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}
