const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');

const userSchema = new mongoose.Schema({
	email: {
		type: String,
		required: [true, 'Email is required'],
		unique: true,
		lowercase: true,
		validate: [validator.isEmail, 'Please provide a valid email']
	},
	password: {
		type: String,
		required: [true, 'Password is required'],
		minlength: 8,
		select: false // Won't be included in queries by default
	},
	role: {
		type: String,
		enum: ['patient', 'doctor', 'admin'],
		default: 'patient'
	},
	firstName: {
		type: String,
		required: [true, 'First name is required'],
		trim: true
	},
	lastName: {
		type: String,
		required: [true, 'Last name is required'],
		trim: true
	},
	phoneNumber: {
		type: String,
		validate: {
			validator: function(v) {
				return /^\+?[\d\s-]+$/.test(v);
			},
			message: '{VALUE} is not a valid phone number'
		}
	},
	passwordResetToken: String,
	passwordResetExpires: Date,
	active: {
		type: Boolean,
		default: true,
		select: false
	},
	lastLogin: Date,
	createdAt: {
		type: Date,
		default: Date.now
	}
}, {
	timestamps: true,
	toJSON: { virtuals: true },
	toObject: { virtuals: true }
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
	if (!this.isModified('password')) return next();

	this.password = await bcrypt.hash(this.password, 12);
	next();
});

// Instance method to check password
userSchema.methods.correctPassword = async function(candidatePassword, userPassword) {
	return await bcrypt.compare(candidatePassword, userPassword);
};

// Instance method to create password reset token
userSchema.methods.createPasswordResetToken = function() {
	const resetToken = crypto.randomBytes(32).toString('hex');

	this.passwordResetToken = crypto
		.createHash('sha256')
		.update(resetToken)
		.digest('hex');

	this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

	return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
