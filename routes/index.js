 const router = require("express").Router();
const bcryptjs = require('bcryptjs')
const User = require('../models/User.model')
const saltRounds = 10
const session = require("express-session")
const mongo = require("connect-mongo")

router.get("/", (req, res, next) => {
  res.render("index");
});
router.get('/signup', (req, res, next) => {
  res.render('auth/sign-up')
})

router.post('/signup', async (req, res, next) => {
  try {
    const { email, password } = req.body
    const salt = await bcryptjs.genSalt(saltRounds)
    const hashedPassword = await bcryptjs.hash(password, salt)
    console.log(`Passwordhash: ${hashedPassword}`)

    const newUser = await User.create({ email, passwordHash: hashedPassword })
    res.redirect('/user-profile')
  } catch (error) {
    if (error.code === 11000) {
      res.render('auth/sign-up', { errorMessage: 'Email already in use' })
    }
    console.log('error create the post route', error)
  }
})

router.get ("/user-profile", (req,res, next)=>{
  res.render('user-profile')
})


///////////////////////////////Login///////////////////////////
router.get('/login', (req, res, next) => {
  res.render('auth/login')
})

router.post('/login', async (req, res, next) => {
  const { email, password } = req.body
  if (email === '' || password === '') {
    res.render('auth/login', { errorMessage: 'please enter email and password' })
    return
  }

  const user = await User.findOne({ email })

  if (!user?.email) {
    res.render('auth/login', { errorMessage: 'This email is not in the DB' })
    return
  }

  if (bcryptjs.compareSync(password, user.passwordHash)) {
    console.log(req.session);
    req.session.currentUser=user
    console.log(req.session);
    res.redirect('/user-profile')
  } else {
    // Wrong password
    res.render('auth/login', { errorMessage: 'Wrong password' })
  }
})

module.exports = router;
