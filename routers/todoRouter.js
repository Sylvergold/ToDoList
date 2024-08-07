const express = require('express');
const { createContent, getOneContent, getAllContent, updateContent, deleteContent } = require('../controllers/todoController');
const { authenticate } = require('../middleware/authorization');
const router = express.Router();

router.post('/create-content', authenticate, createContent);

router.get('/one-content/:todoId', authenticate, getOneContent);

router.get('/all-content/', authenticate, getAllContent);

router.patch('/update-content/:todoId', authenticate, updateContent);

router.delete('/delete-content/:todoId', authenticate, deleteContent);

module.exports = router