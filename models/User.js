// --- models/User.js ---
// This file is our blueprint for the member folders in the toy box.

const mongoose = require("mongoose");
const passportLocalMongoose = require("passport-local-mongoose");

const UserSchema = new mongoose.Schema({
  // passport-local-mongoose will automatically add username, hash, and salt fields.
  // We can add other fields specific to our users here:
  favoriteColor: {
    type: String,
    default: "blue", // A default favorite color if not provided
  },
  // You could add other fields here, like mobile number, etc.
  // mobileNumber: { type: String, unique: true, sparse: true } // sparse for optional unique
});

// Apply the passport-local-mongoose plugin to our schema.
// This gives us helper methods like User.register, User.authenticate, serializeUser, deserializeUser.
UserSchema.plugin(passportLocalMongoose);

// Export our User model so the main clubhouse file can use it.
module.exports = mongoose.model("User", UserSchema);
