const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
require('dotenv').config();

// Initialize Express app
const app = express();

// Logger configuration
const logger = winston.createLogger({
	level: 'info',
	format: winston.format.combine(
		winston.format.timestamp(),
		winston.format.json()
	),
	transports: [
		new winston.transports.File({ filename: 'error.log', level: 'error' }),
		new winston.transports.File({ filename: 'combined.log' })
	]
});

if (process.env.NODE_ENV !== 'production') {
	logger.add(new winston.transports.Console({
		format: winston.format.simple()
	}));
}

// Security Middleware
app.use(helmet());
app.use(cors({
	origin: process.env.FRONTEND_URL || 'http://localhost:4200',
	credentials: true
}));

// Rate limiting
const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Body parser middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get('/health', (req, res) => {
	res.status(200).json({ status: 'ok' });
});

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/healthcare-system', {
	useNewUrlParser: true,
	useUnifiedTopology: true
})
	.then(() => {
		logger.info('MongoDB Connected');
	})
	.catch(err => {
		logger.error('MongoDB Connection Error:', err);
	});

// Error handling middleware
app.use((err, req, res, next) => {
	logger.error(err.stack);
	res.status(500).json({
		success: false,
		message: process.env.NODE_ENV === 'production'
			? 'Internal server error'
			: err.message
	});
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
	logger.info(`Server running on port ${PORT}`);
});

module.exports = app; // For testing purposes
