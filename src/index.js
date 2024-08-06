const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const Router = require('../src/routes');
const errorHandler = require('../src/middleware/errorHandlee');

//mongodb+srv://eg69228:<password>@users.jyqzlop.mongodb.net/?retryWrites=true&w=majority&appName=users
//uFnnvsepc9W5WgtD
dotenv.config();

const app = express();
const PORT  = process.env.PORT || 5000; // Corrigido o valor padrão da porta para 5000

app.use(express.json());
app.use('/api', Router);
app.use(errorHandler);

mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('Connected to MongoDB');
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    })
    .catch((error) => {
        console.error('MongoDB connection error:', error);
    });