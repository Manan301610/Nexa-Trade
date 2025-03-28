const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
   username: {
      type: String,
      required: true,
      unique: true,
   },
   email: {
      type: String,
      required: true,
      unique: true,
   },
   password: {
      type: String,
      required: true, // Hashing will be handled in the backend
   },
});

module.exports = mongoose.model('User', userSchema);
