const express = require('express');
const { userSignUp, userLogin, signOut, verifyEmail, resendVerificationEmail, changePassword, resetPassword, forgotPassword, getAll, deleteUser, oneUser } = require('../controllers/userController');
const { authenticate, isAdmin } = require('../middleware/authorization');
const router = express.Router();

// Get all users route for Admin
router.get('/user/all', authenticate, isAdmin, getAll);
// get one user
router.get('/user/one/:userId', oneUser);
// Delete a user for admin
router.delete('/user/one/:userId', authenticate, isAdmin, deleteUser);

router.route('/user/sign-up').post(userSignUp)

router.route('/user/log-in').post(userLogin)

router.route('/log-out/:userId').post(authenticate, signOut)

router.route("/user/verify-email/:token")
    .get(verifyEmail);

router.route("/user/resend-verification-email")
    .post(resendVerificationEmail);

router.route('/user/change-password/:token')
    .post(changePassword);

router.route('/user/reset-password/:token')
    .post(resetPassword);

router.route('/user/forgot-password')
    .post(forgotPassword);

module.exports = router;
