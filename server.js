// --- server.js ---
// This is the main file for our clubhouse. It sets up everything!

// 1. Get all our building tools (dependencies)
const express = require("express"); // Our clubhouse framework
const mongoose = require("mongoose"); // Our magic helper for the toy box
const passport = require("passport"); // Our friendly doorman
const JwtStrategy = require("passport-jwt").Strategy; // Special doorman tool for JWTs
const ExtractJwt = require("passport-jwt").ExtractJwt; // Another doorman tool to find the JWT
const LocalStrategy = require("passport-local").Strategy; // Doorman tool for username/password login
const User = require("./models/User"); // Our blueprint for member folders
const bcrypt = require("bcryptjs"); // A super secret code maker for passwords (passport-local-mongoose uses this internally)
const jwt = require("jsonwebtoken"); // Tool to create and check the magical stickers (JWTs)
const cors = require("cors"); // Helps our mobile app talk to the server even if they are in different places

// A super secret code for making our JWT stickers.
// In a real app, this should be in an environment variable (like a hidden safe!).
const JWT_SECRET = "your_super_secret_jwt_key";

// 2. Start our Express clubhouse
const app = express();

// 3. Connect to our MongoDB giant toy box
// Make sure you have MongoDB running on your computer (or a cloud service)!
mongoose
  .connect("mongodb://localhost:27017/authClubDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to the giant toy box!"))
  .catch((err) =>
    console.error("Oh no, could not connect to the toy box:", err)
  );

// 4. Add middlewares to our clubhouse
// These are like special filters for all messages coming into the clubhouse.
app.use(cors()); // Allow messages from different places (like your mobile app)
app.use(express.json()); // Helps our clubhouse understand messages in JSON format
app.use(express.urlencoded({ extended: true })); // Helps with simple form data

// 5. Initialize our doorman (Passport.js)
app.use(passport.initialize()); // Get the doorman ready for duty!

// 6. Tell the doorman how to check username/password (Local Strategy)
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username }); // Ask Mongoose to find the member's folder
      if (!user) {
        // If no user is found, tell the doorman to say "no member found"
        return done(null, false, { message: "Incorrect username." });
      }

      // Compare the password provided with the stored password (handled by passport-local-mongoose)
      // We're using User.authenticate from passport-local-mongoose
      const isValidPassword = await user.authenticate(password);
      if (!isValidPassword.user) {
        // passport-local-mongoose's authenticate returns { user, error }
        return done(null, false, { message: "Incorrect password." });
      }

      // If everything is good, tell the doorman this user is allowed!
      return done(null, user);
    } catch (err) {
      // If something went wrong, tell the doorman there's a problem
      return done(err);
    }
  })
);

// 7. Tell the doorman how to check the magical JWT stickers (JWT Strategy)
// This part tells Passport how to take the JWT from the incoming message
// and verify it.
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), // Tells Passport to look for the JWT in the 'Authorization: Bearer <token>' header
  secretOrKey: JWT_SECRET, // The super secret code used to sign and verify the JWT
};

passport.use(
  new JwtStrategy(jwtOptions, async (jwt_payload, done) => {
    // When Passport gets a JWT, it decodes it and gives us the 'payload' (the info inside).
    // Now, we need to find the user based on the info in the payload (e.g., user ID).
    try {
      const user = await User.findById(jwt_payload.id); // Assuming we put 'id' in the JWT payload

      if (user) {
        // If the user exists, tell the doorman this JWT is good!
        return done(null, user);
      } else {
        // If no user found for this ID in the JWT, or JWT is bad
        return done(null, false);
      }
    } catch (err) {
      // If something went wrong during database lookup
      return done(err, false);
    }
  })
);

// --- Routes for our Clubhouse Doors ---
// These are the specific paths (doors) that our mobile app can talk to.

// 8. Door for new members to register
app.post("/register", async (req, res) => {
  const { username, password, favoriteColor } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required!" });
  }

  try {
    // Create a new member folder with their username and other details
    const newUser = new User({ username, favoriteColor });
    // Use User.register() from passport-local-mongoose to hash the password and save
    await User.register(newUser, password);
    res.status(201).json({ message: "Welcome to the club, new member!" });
  } catch (err) {
    // If something goes wrong (e.g., username already taken)
    console.error("Registration error:", err);
    res.status(400).json({ message: "Couldn't sign you up: " + err.message });
  }
});

// 9. Door for existing members to log in and get their magical sticker (JWT)
app.post("/login", (req, res, next) => {
  // We use passport.authenticate('local') here to check username/password
  // session: false because we don't want to use traditional sessions; we use JWTs instead.
  passport.authenticate("local", { session: false }, (err, user, info) => {
    if (err || !user) {
      // If there's an error or no user, login failed
      return res.status(400).json({
        message: "Login failed",
        user: user,
        info: info,
      });
    }
    req.login(user, { session: false }, (err) => {
      if (err) {
        res.send(err);
      }
      // If login is successful, create the magical JWT sticker!
      const token = jwt.sign(
        { id: user._id, username: user.username }, // What info to put in the sticker (payload)
        JWT_SECRET, // Our super secret code to sign it
        { expiresIn: "1h" } // How long the sticker is valid (1 hour)
      );
      // Send the magical sticker back to the mobile app
      return res.json({
        message: "You're in the club!",
        token: token,
        user: {
          id: user._id,
          username: user.username,
          favoriteColor: user.favoriteColor,
        },
      });
    });
  })(req, res, next);
});

// 10. VIP Door (Protected Route) - Only accessible with a valid JWT
app.get(
  "/secret-members-only-info",
  passport.authenticate("jwt", { session: false }), // Passport checks the JWT sticker here!
  (req, res) => {
    // If Passport says the JWT is good, this code runs.
    res.json({
      message: `Shhh, this is top-secret info for ${req.user.username}!`,
      yourFavoriteColor: req.user.favoriteColor,
      userId: req.user._id,
    });
  }
);

// 11. Another VIP Door - Example of another protected resource
app.get(
  "/club-games",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.json({
      message: `Hey ${req.user.username}, here are the fun games in the club!`,
      games: ["Hide and Seek", "Tag", "Building Blocks", "Pictionary"],
    });
  }
);

// 12. Start our clubhouse listening for messages
const PORT = process.env.PORT || 3000; // Use port 3000 or whatever is available
app.listen(PORT, () => {
  console.log(`Clubhouse is open and listening on port ${PORT}!`);
});
