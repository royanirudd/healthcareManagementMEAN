const jwt = require('jsonwebtoken');
const User = require('../models/user.model');
const AppError = require('../utils/AppError');
const { promisify } = require('util');

const signToken = (id) => {
	return jwt.sign(
		{ id },
		process.env.JWT_SECRET,
		{ expiresIn: process.env.JWT_EXPIRES_IN || '1d' }
	);
};

const createSendToken = (user, statusCode, res) => {
	const token = signToken(user._id);

	// Remove password from output
	user.password = undefined;

	res.status(statusCode).json({
		status: 'success',
		token,
		data: { user }
	});
};

exports.register = async (req, res, next) => {
	try {
		const newUser = await User.create({
			firstName: req.body.firstName,
			lastName: req.body.lastName,
			email: req.body.email,
			password: req.body.password,
			role: req.body.role,
			phoneNumber: req.body.phoneNumber
		});

		createSendToken(newUser, 201, res);
	} catch (err) {
		next(new AppError(err.message, 400));
	}
};

exports.login = async (req, res, next) => {
	try {
		const { email, password } = req.body;

		// Check if email and password exist
		if (!email || !password) {
			return next(new AppError('Please provide email and password', 400));
		}

		// Check if user exists && password is correct
		const user = await User.findOne({ email }).select('+password');

		if (!user || !(await user.correctPassword(password, user.password))) {
			return next(new AppError('Incorrect email or password', 401));
		}

		// Update last login
		user.lastLogin = Date.now();
		await user.save({ validateBeforeSave: false });

		createSendToken(user, 200, res);
	} catch (err) {
		next(new AppError(err.message, 400));
	}
};

exports.protect = async (req, res, next) => {
	try {
		// Get token and check if it exists
		let token;
		if (req.headers.authorization?.startsWith('Bearer')) {
			token = req.headers.authorization.split(' ')[1];
		}

		if (!token) {
			return next(new AppError('You are not logged in', 401));
		}

		// Verify token
		const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

		// Check if user still exists
		const user = await User.findById(decoded.id);
		if (!user) {
			return next(new AppError('User no longer exists', 401));
		}

		// Grant access to protected route
		req.user = user;
		next();
	} catch (err) {
		next(new AppError('Authentication failed', 401));
	}
};

exports.restrictTo = (...roles) => {
	return (req, res, next) => {
		if (!roles.includes(req.user.role)) {
			return next(new AppError('You do not have permission', 403));
		}
		next();
	};
};
