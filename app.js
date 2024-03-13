//jshint esversion:6
//level 1 -- simple login using mongo
//level 2 -- encrypting the password in database using mongoose-encryption
// -- using envvionment variables or env to hide keys or secret codes like encrytion pattern
//level3 -- using md5 hasing we hash the entered password and store it in data base and hasing is irrriversable so we will compare the hash data while login
//level4 -- salting -- we will add some extra random characters to the users original password and then  hash it.
//we will be using a more secure hasing algo bcrypt+salting so it will be more difficult to create a hash table for hackers
//we can also repeate this process like we can take the salted hash and add more salt and hash it again and again

require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt  = require("mongoose-encryption");
//const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

app.use(
  session({
    secret: "My Secret Code",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//userSchema.plugin(encrypt,{secret: process.env.SECRET, encryptedFields:['password']});

const User = mongoose.model("User", userSchema);
passport.use(User.createStrategy());
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id).then((user) => {
    done(null, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIEND_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);
app.get("/login", function (req, res) {
  res.render("login");
});
app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  User.find({"secret": {$ne: null}})
      .then(foundUsers => {
          res.render("secrets", { usersWithSecrets: foundUsers });
      })
      .catch(err => {
          console.log(err);
          res.status(500).send("Internal Server Error");
      });
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      console.log(err);
    }
  });
  res.redirect("/");
});
app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});
// app.post("/submit", async function (req, res) {
//   const submittedSecret = req.body.secret;
//   try {
//     const foundUser = await User.findById(req.user.id);
//     if (foundUser) {
//       console.log("userFound");
//       foundUser.secret = submittedSecret;
//       await foundUser.save();
//       res.redirect("secrets");
//     } else {
//       console.log("User not found");
//       throw new Error("User not found");
//     }
//   } catch (error) {
//     console.log("Error:", error);
//     res.redirect("/");
//   }
// });


app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;
  console.log(req.user.id);
  User.findById(req.user.id)
    .then(foundUser => {
      if (foundUser) {
        console.log("userFound");
        foundUser.secret = submittedSecret;
        return foundUser.save();
      } else {
        console.log("User not found");
        res.redirect("/"); // Redirect to a suitable page or handle the error appropriately
        return null; // Returning null to break the promise chain
      }
    })
    .then(savedUser => {
      if (savedUser) {
        res.redirect("secrets");
      }
    })
    .catch(error => {
      console.log("Error:", error);
      res.redirect("/"); // Redirect to a suitable page or handle the error appropriately
    });
});







app.post("/register", function (req, res) {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});
app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });
  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});
// app.post("/register",function(req,res) {
//     bcrypt.hash(req.body.password,saltRounds,function(err, hash){
//         const newUser = new User({
//             email: req.body.username,
//             //password: md5(req.body.password)
//             password: hash
//             //password: req.body.password
//         });

//         newUser.save().then(()=>{
//             res.render("secrets");
//         }).catch((err)=>{
//             console.log(err);
//         });
//     });
// });

// app.post("/login", function (req,res) {
//     const username = req.body.username;
//     //const password = md5(req.body.password);
//     //const password = req.body.password;
//     const password = req.body.password;
//     User.findOne({email: username}).then((data) => {
//         if (data) {
//           bcrypt.compare(password, data.password, function(err,result){
//             if (result) {
//                 res.render("secrets");
//             } else {
//                 res.send('<h1>Wrong Password</h1>');
//             }
//           })
//         }else{
//             console.log("User Not Found");
//             res.send("<h1>User not found</h1>");
//         }
//     }).catch((err) => console.log(err));
//   })

app.listen(3000, function () {
  console.log("Server has started!");
});
