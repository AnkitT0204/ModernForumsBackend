const mongoose = require('mongoose');

const boardSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true }, // e.g., "b"
  description: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Board', boardSchema);