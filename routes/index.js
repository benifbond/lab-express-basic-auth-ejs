const router = require("express").Router();
const bcryptjs = require('bcryptjs')
const User = require('../models/User.model')
const saltRounds = 10
const session = require("express-session")
const mongo = require("connect-mongo")

/* GET home page */
router.get("/", (req, res, next) => {
  res.render("index");
});

/*Get to Sign Up*/
router.get("/sign-up", (req, res, next) => {
  res.render("sign-up");
});

router.post("/sign-up", (req, res, next) => {

  const { username, email, password } = req.body;

  bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      return User.create({
        username,
        email,
        password: hashedPassword
      });
    })
    .then(userFromDB => {
      console.log('Newly created user is: ', userFromDB);

    })
    .then( () => {
      res.redirect('user-profile')
    })
    .catch(error => next(error))
});

/*Get to Login*/
router.get("/login", (req, res, next) => {
  res.render("login");
});

router.post('/login', (req, res, next) => {
  const { email, password } = req.body;
 
 if (email === '' || password === '') {
    res.render('login', {
      errorMessage: 'Please enter both, email and password to login.'
    });
    return;
  }
  User.findOne({ email }) // <== check if there's user with the provided email
    .then(user => {
      // <== "user" here is just a placeholder and represents the response from the DB
      if (!user) {
        // <== if there's no user with provided email, notify the user who is trying to login
        res.render('login', {
          errorMessage: 'Email is not registered. Try with other email.'
        });
        return;
      }
 
      // if there's a user, compare provided password
      // with the hashed password saved in the database
      else if (bcryptjs.compareSync(password, user.password)) {
        // if the two passwords match, render the user-profile.ejs and
        //                   pass the user object to this view
        //                                 |
        //                                 V
        res.render('user-profile', { user });
      } else {
        // if the two passwords DON'T match, render the login form again
        // and send the error message to the user
        res.render('login', { errorMessage: 'Incorrect password.' });
      }
    })
    .catch(error => next(error));
});

module.exports = router;
