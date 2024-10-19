
const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config();

const connect = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected to MongoDB');
    } catch (error) {
        console.log('Error connecting to MongoDB:', error);
    }
}

module.exports = { connect };