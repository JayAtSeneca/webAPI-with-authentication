const express = require("express");
const cors = require("cors");
const jwt = require('jsonwebtoken');
const passport = require('passport');
const passportJWT = require('passport-jwt');
const dataService = require("./data-service.js");
const userService = require("./user-service.js");
const app = express();


// JSON Web Token Setup
let ExtractJwt = passportJWT.ExtractJwt;
let JwtStrategy = passportJWT.Strategy;

// Configure its options
let jwtOptions = {};
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme('jwt');

// IMPORTANT - this secret should be a long, unguessable string
// (ideally stored in a "protected storage" area on the web server).
// We suggest that you generate a random 50-character string
// using the following online tool:
// https://lastpass.com/generatepassword.php

jwtOptions.secretOrKey = process.env.SECRET_OR_KEY;

let strategy = new JwtStrategy(jwtOptions, function (jwt_payload, next) {
  console.log('payload received', jwt_payload);

  if (jwt_payload) {
    // The following will ensure that all routes using
    // passport.authenticate have a req.user._id, req.user.userName, req.user.fullName & req.user.role values
    // that matches the request payload data
    next(null, {
      _id: jwt_payload._id,
      userName: jwt_payload.userName,
      fullName: jwt_payload.fullName,
      role: jwt_payload.role,
    });
  } else {
    next(null, false);
  }
});


app.use(express.json());
app.use(cors());
// tell passport to use our "strategy"
passport.use(strategy);
// add passport as application-level middleware
app.use(passport.initialize());


const HTTP_PORT = process.env.PORT || 8080;

app.get("/api/vehicles", passport.authenticate('jwt', { session: false }), (req, res) => {
  dataService
    .getAllVehicles()
    .then((data) => {
      res.json(data);
    })
    .catch(() => {
      res.status(500).end();
    });
});

app.post("/api/register", (req, res) => {
  userService
    .registerUser(req.body)
    .then((msg) => {
      res.json({ message: msg });
    })
    .catch((msg) => {
      console.log("In the catch statement");
      res.status(422).json({ message: msg });
    });
});

app.post("/api/login", (req, res) => {

    

    userService
    .checkUser(req.body)
    .then((user) => {
      let payload = {
        _id: user._id,
        userName: user.userName,
        fullName: user.fullName,
        role: user.role,
      };
      
      let token = jwt.sign(payload, jwtOptions.secretOrKey);
        res.json({ message: 'login successful', token: token });
    })
    .catch((msg) => {
        res.status(422).json({ message: msg });
    });
});

app.use((req, res) => {
  res.status(404).end();
});

userService
  .connect()
  .then(() => {
    app.listen(HTTP_PORT, () => {
      console.log("API listening on: " + HTTP_PORT);
    });
  })
  .catch((err) => {
    console.log("unable to start the server: " + err);
    process.exit();
  });
