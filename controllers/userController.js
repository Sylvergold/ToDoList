require('dotenv').config();
const userModel = require('../models/userModel')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { sendEmail } = require('../middleware/sendMail');



// user sign up
exports.userSignUp = async (req, res) => {
    try {
        const { email, password, fullName } = req.body
        if (!email || !password || !fullName) {
            return res.status(400).json({
                message: `Please enter all details`
            })
        }
        const emailExists = await userModel.findOne({ email: email.toLowerCase() });
        if (emailExists) {
            return res.status(400).json({
                message: `Email already exist.`
            })
        }

        // salt the password using bcrypt
        const salt = bcrypt.genSaltSync(10)
        // hash the salted password using bcrypt
        const hashedPassword = bcrypt.hashSync(password, salt);

        // create a user
        const user = new userModel({
            email,
            password: hashedPassword,
            fullName
        });

        // create a token
        const token = jwt.sign({
            userId: user._id,
            email: user.email,
        },
            process.env.JWT_SECRET, { expiresIn: "50 mins" })

        // Assign the created token to the user's token field
        user.token = token

        // send verification email
        const mailOptions = {
            email: user.email,
            subject: "Verify your account",
            html: `Please click on the link to verify your email: <a href="https://cohort-4-todo-app-cmzo.onrender.com/api/user/verify-email/${token}">Verify Email</a>`,
        };

        // save the user
        await user.save();

        await sendEmail(mailOptions);

        // return a response
        res.status(201).json({
            message: `Check your email: ${user.email} to verify your account.`,
            data: user
        })

    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}




// verify email
exports.verifyEmail = async (req, res) => {
    try {
        const { token } = req.params;

        if (!token) {
            return res.status(404).json({
                error: "Token not found"
            })
        }

        // verify the token
        const { email } = jwt.verify(token, process.env.JWT_SECRET);

        const user = await userModel.findOne({ email });

        if (!user) {
            return res.status(404).json({
                error: "User not found"
            });
        }

        // Check if user has already been verified
        if (user.isVerified) {
            return res.status(400).json({
                error: "User already verified"
            });
        }

        // update the user verification
        user.isVerified = true;

        // save the changes
        await user.save();

        res.status(200).json({
            message: "User verified successfully",
            // data: user,
        })
        // res.status( 200 ).redirect( `${req.protocol}://${req.get("host")}/api/log-in` );

    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            return res.status(404).json({
                message: "Session timed-out."
            });
        }
        res.status(500).json({
            message: error.message
        })
    }
}




// resend verification
exports.resendVerificationEmail = async (req, res) => {
    try {
        // get user email from request body
        const { email } = req.body;

        // find user
        const user = await userModel.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({
                error: "User not found"
            });
        }

        // Check if user has already been verified
        if (user.isVerified) {
            return res.status(400).json({
                error: "User already verified"
            });
        }

        // create a token
        const token = await jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "50m" });

        // send verification email
        const mailOptions = {
            email: user.email,
            subject: "Email Verification",
            html: `Please click on the link to verify your email: <a href="https://cohort-4-todo-app-cmzo.onrender.com/api/user/verify-email/${token}">Verify Email</a>`,
        };

        await sendEmail(mailOptions);

        res.status(200).json({
            message: `Verification email sent successfully to your email: ${user.email}`
        });

    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}





// Forgot Password
exports.forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        // Check if the email exists in the userModel
        const user = await userModel.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        // Generate a reset token
        const resetToken = await jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "30m" });

        // Send reset password email
        const mailOptions = {
            email: user.email,
            subject: "Password Reset",
            html: `Please click on the link to reset your password: <a href="https://cohort-4-todo-app-cmzo.onrender.com/api/user/reset-password/${resetToken}">Reset Password</a> link expires in 30 minutes`,
        };

        await sendEmail(mailOptions);

        res.status(200).json({
            message: "Password reset email sent successfully"
        });
    } catch (error) {
        console.error("Something went wrong", error.message);
        res.status(500).json({
            message: error.message
        });
    }
};


// Reset Password
exports.resetPassword = async (req, res) => {
    try {
        const { token } = req.params;
        const { password } = req.body;

        // Verify the user's token
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

        // Get the user's Id from the token
        const userId = decodedToken.userId;

        // Find the user by ID
        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        // Salt and hash the new password
        const saltedRound = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, saltedRound);

        // Update the user's password
        user.password = hashedPassword;
        await user.save();

        res.status(200).json({
            message: "Password reset successful"
        });
    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            return res.status(404).json({
                message: "Session timed-out."
            });
        }
        console.error("Something went wrong", error.message);
        res.status(500).json({
            message: error.message
        });
    }
};





// User login
exports.userLogin = async (req, res) => {
    try {
        // Extract the user's email and password
        const { password, email } = req.body;
        if (!email || !password) {
            return res.status(400).json({
                message: `Please enter all details`
            })
        }

        // find user by their registered email or username
        const checkUser = await userModel.findOne({ email: email.toLowerCase() })

        // check if the user exists
        if (!checkUser) {
            return res.status(404).json({
                Failed: 'User not found'
            })
        }

        // Compare user's password with the saved password.
        const checkPassword = bcrypt.compareSync(password, checkUser.password)
        // Check for password error
        if (!checkPassword) {
            return res.status(404).json({
                message: 'Invalid password'
            })
        }

        // Check if the user if verified
        if (!checkUser.isVerified) {
            return res.status(404).json({
                message: `User with this email: ${email} is not verified.`
            })
        }

        const token = jwt.sign({
            userId: checkUser._id,
            email: checkUser.email,
            isAdmin: checkUser.isAdmin
        },
            process.env.JWT_SECRET, { expiresIn: "50 mins" })

        checkUser.save()

        res.status(200).json({
            message: 'Login successful',
            data: checkUser,
            token

        })

    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}





// Change Password
exports.changePassword = async (req, res) => {
    try {
        const { token } = req.params;
        const { password, existingPassword } = req.body;

        // Verify the user's token
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

        // Get the user's Id from the token
        const userId = decodedToken.userId;

        // Find the user by ID
        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        // Confirm the previous password
        const isPasswordMatch = await bcrypt.compare(existingPassword, user.password);
        if (!isPasswordMatch) {
            return res.status(401).json({
                message: "Existing password does not match"
            });
        }

        // Salt and hash the new password
        const saltedRound = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, saltedRound);

        // Update the user's password
        user.password = hashedPassword;
        await user.save();

        res.status(200).json({
            message: "Password changed successful"
        });
    } catch (error) {
        if (error instanceof jwt.JsonWebTokenError) {
            return res.status(404).json({
                message: "Session timed-out."
            });
        }
        console.error("Something went wrong", error.message);
        res.status(500).json({
            message: error.message
        });
    }
};




// User sign out
exports.signOut = async (req, res) => {
    try {
        const { userId } = req.user;

        // Update the user's token to null
        const user = await userModel.findByIdAndUpdate(userId, { token: null }, { new: true });

        if (!user) {
            return res.status(404).json({
                message: 'User not found',
            });
        }
        res.status(200).json({
            message: 'User logged out successfully',
        });
    } catch (error) {
        res.status(500).json({
            message: error.message,
        });
    }
};

exports.getAll = async (req, res) => {
    try {
        const allUsers = await userModel.find();
        res.status(200).json({
            message: 'List of all users in the database',
            allUsers
        })
    } catch (error) {
        res.status(500).json({
            message: error.message,
        }); 
    }
}

exports.deleteUser = async (req, res) => {
    try {
        const {userId} = req.params;
        const deletedUser = await userModel.findByIdAndDelete(userId);
        if(!deletedUser){
            return res.status(404).json({
                message: "User not found"
            })
        }

        res.status(200).json({
            message: 'User deleted successfully'
        })
    } catch (error) {
        res.status(500).json({
            message: error.message,
        }); 
    }
}

exports.oneUser = async (req, res) => {
    try {
        const { userId} =req.params;
        const user = await userModel.findById(userId);
        res.status(200).json({
            message: 'User details found',
            data: user
        })
    } catch (error) {
        res.status(500).json({
            message: error.message,
        });  
    }
}
