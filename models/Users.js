const mongoose = require('mongoose')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')

let userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    hash: String,
    salt: String,
    userSince: {
        type: Date,
        default: Date.now()
    },
    realName: {
        type: String,
        required: true
    }
})

userSchema.methods.setPassword = function(password) {
    this.salt = crypto.randomBytes(16).toString('hex')
    this.hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex')
}

userSchema.methods.validatePassword = function(password) {
    const hash = crypto.pbkdf2Sync(password, this.salt, 10000, 512, 'sha512').toString('hex')
    return this.hash === hash
}

/*userSchema.methods.generateJWT = function() {
    const today = new Date()
    const expirationDate = new Date(today)
    expirationDate.setDate(today.getDate() + 60)

    return jwt.sign({
        email: this.email,
        username: this.username,
        id: this._id,
        exp: parseInt(expirationDate.getDate() / 1000, 10)
    }, 'secret')
}

userSchema.methods.toAuthJSON = function() {
    return {
      _id: this._id,
      email: this.email,
      token: this.generateJWT(),
    }
  }
*/
module.exports = mongoose.model('Users', userSchema)