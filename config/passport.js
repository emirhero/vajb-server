const mongoose = require('mongoose')
const passport = require('passport')
const LocalStrategy = require('passport-local')

const Users = require('../models/Users')

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, (email, password, done) => {
    Users.findOne({ email: usernameField })
         .then((user) => {
             if (!user || !user.validatePassword(password)) {
                 return done(null, false, { errors: {'email ili password' : 'nije tacan'} })
             }

             return done(null, user)
         }).catch(done)
}))