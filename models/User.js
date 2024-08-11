const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true},
    email: { type: String, required: true, unique: true },
    password: { type: String, require: true},
    age: { type: Number, required: true},
    location: { type: String, required: true},
    profilePicture: { type: Buffer},
    description: { type: String},
});

const User = mongoose.model('User', UserSchema);

module.exports = User;