const { Router } = require('express');
const router = new Router();
 
 
module.exports = router

const { isLoggedIn, isLoggedOut } = require('../middleware/route.guard.js');
router.get('/userProfile', isLoggedIn, (req, res) => {
    res.render('users/user-profile', { userInSession: req.session.currentUser });
  });
  router.get('/signup', isLoggedOut, (req, res) => res.render('auth/signup'));