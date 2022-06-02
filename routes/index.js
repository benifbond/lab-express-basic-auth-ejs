const router = require("express").Router();
const bcryptjs = require('bcryptjs')
const User = require('../models/User.model')
const saltRounds = 10
const session = require("express-session")
const mongo = require("connect-mongo")


router.get("/", (req, res, next) => {
  res.render("index");
});

router.get("/signup", (req, res, next) => {
  res.render("sign-up");
});

router.post('/sign-up', (req, res, next) => {
  const { username, email, password } = req.body
  if (!username || !email || !password) {
    res.render('sign-up', {
      errorMessage: 'All fields are mandatory. Please provide your username, email and password.',
    })
    return
  }
  const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/
  if (!regex.test(password)) {
    res.status(500).render('sign-up', {
      errorMessage:
        'Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.',
    })
    return
  }

  bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      return User.create({
        username,
        email,
        password: hashedPassword,
      })
    })
    .then(userFromDB => {
      res.redirect('/userProfile',{userFromDB})
    })
    .catch(error => {
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render('sign-up', { errorMessage: error.message })
      } else if (error.code === 11000) {
        res.status(500).render('sign-up', {
          errorMessage:
            'Username and email need to be unique. Either username or email is already used.',
        })
      } else {
        next(error)
      }
    }) 
})



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
