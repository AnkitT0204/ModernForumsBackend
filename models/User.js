const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'moderator', 'admin'], default: 'user' },
  moderatorBoards: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Board' }], // Boards user moderates
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('User', userSchema);