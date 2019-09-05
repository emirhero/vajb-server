const express = require('express')
const mongoose = require('mongoose')
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const passport = require('passport')
const LocalStrategy = require('passport-local')
const passportJWT = require('passport-jwt')
const JWTStrategy = passportJWT.Strategy
const ExtractJWT = passportJWT.ExtractJwt

const axios = require('axios')
const sanitize = require('mongo-sanitize')
const uri = require('uri-js') 

// Mongo configuration
const mongoLink = 'mongodb://overlord:f1bonacci@ds145346.mlab.com:45346/the-brain'
mongoose.connect(mongoLink, { useNewUrlParser: true })
const db = mongoose.connection
db.on('error', console.error.bind(console, 'Error connecting to MongoDB: '))

const app = express()

const jsonParser = bodyParser.json()

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*')
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization')

    next()
})

let updated = Date.now()

const Users = require('./models/Users')

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, (email, password, done) => {
    Users.findOne({ email })
         .then((user) => {
             if (!user || !user.validatePassword(password)) {
                 return done(null, false, { errors: {'email ili password' : 'nije tacan'} })
             }

             return done(null, user, {message: 'Login uspjesan!'})
         }).catch(error => console.log(error))
}))

passport.use(new JWTStrategy({
    jwtFromRequest: ExtractJWT.fromHeader('authorization'),
    secretOrKey: 'hugesecret'
}, function(jwtPayload, done) {
    Users.findOne({ username: jwtPayload.username }, function(err, user) {
        if(err) {
            return done(err, false)
        }
        else if(user) {
            return done(null, user)
        } else {
            return done(null, false)
        }
    })
}))


/*const auth = {
    required: jwt({
        secret: 'secret',
        userProperty: 'payload',
        getToken: getTokenFromHeaders
    }),
    optional: jwt({
        secret: 'secret',
        userProperty: 'payload',
        getToken: getTokenFromHeaders,
        credentialsRequired: false
    })
}*/

let pinSchema = new mongoose.Schema({
    pinboard: {
        type: String,
        required: true
    },
    link: {
        type: String,
        required: true
    },
    vibes: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Users'
    }],
    by: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Users',
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now()
    }
})

let Pin = mongoose.model('Pin', pinSchema)

app.get('/pins/:pinId', (req, res) => {
    res.send(req.params.pinId)
})

app.post('/pins', passport.authenticate('jwt', {session: false}), jsonParser, async (req, res) => {
    // THE PLAN:
    //
    // 1. Mongoose sanitation                   CHECK
    // 2. Not allowing redirects or 404 pages   CHECK
    // 3. Only allowing specific MIME types     pending...


    // Mongoose sanitization

    //if (body) {
        try {
            let isLinkValid = await checkLink(req)
            if (isLinkValid) {
                let newPin = new Pin({
                    pinboard: req.body.pinboard,
                    link: req.body.link,
                    by: req.user._id
                }) 
                try {
                    let response = await newPin.save()
                    markUpdateTime()
                    res.send(response)
                } catch (error) {
                    res.send(error)
                } 
            } 
        } catch (error) {
            res.status(400).json({error})
        }
 

        /*let linkHeader 
        try {
            linkHeader = await axios.head(body.link)
            if (!linkHeader) throw new Error('Nešto se sjebalo i nismo mogli do tvog linka.')
        } catch (err) {
            res.status(400).send('Nešto se sjebalo i nismo mogli do tvog linka.')
        }

        let linkStatus = linkHeader.status
        //let contentType = linkHeader.header['content-type'] // The format apparently changes
        let bannedMIME = ['application/octet-stream', 'application/zip', 'application/x-7z-compressed']

        if (linkStatus == '200') {

            //if (!bannedMIME.includes(contentType)) {
                try {
                    let response = await newPin.save()
                    markUpdateTime()
                    res.send(response)
                } catch (error) {
                    res.send(error)
                }   
            /*} else {
                res.error(400).json({
                    error: 'Sori! Ne podržavamo taj tip linkova.'
                })
            }*/  
        /*} else {
            res.status(400).send('This link can\'t be pinned')
        }

    } else {
        // BUG: Doesn't get here
        res.error(400)
    }*/
})

app.post('/checkLink', jsonParser, async function (req, res) {
    try {
        let isLinkValid = await checkLink(req)
        if (isLinkValid) {
            res.sendStatus(200)
        }
    } catch (error) {
        res.status(400).json({error: error.message})
    }
})

async function checkLink(req) {
    const BANNED_MIMES = ['application/octet-stream', 'application/zip', 'application/x-7z-compressed'] 

    let body = sanitize(req.body)

    if (Object.entries(body).length === 0) {
        throw new Error('Nešto se sjebalo i nismo mogli do tvog linka.')
    } else {
        // Request is valid
        // We can now check if the link's header passes validation
        try {
            let head = await axios.head(body.link)
            let status = head.status
            let headers = head.headers

            if (!status === 200) {
                throw new Error('Nešto se sjebalo i nismo mogli do tvog linka.')
            } else {
                let contentType = headers['content-type'].split(';')
                console.log(contentType)
                if (BANNED_MIMES.indexOf(contentType) === -1) {
                    return true
                } else {
                    throw new Error('Ne podržavamo ovaj tip linkova.')
                }
            }
        } catch (error) {
            throw new Error('Nešto se sjebalo i nismo mogli do tvog linka.')
        }
    }
}


app.put('/pins/:pinId', passport.authenticate('jwt', {session: false}), async (req, res) => {
    // If the user already vibed, it's gonna unvibe
    try {
        let pin = await Pin.findOne({_id: req.params.pinId})
        let userAlreadyVibed = false
        
        if (pin.vibes.length === 0) {
            pin.vibes.push(req.user._id)          
        } else {
            pin.vibes.forEach((vibe, index) => {
                if (vibe._id.toString() === req.user._id.toString()) {
                    console.log('userAlreadyVibed')
                    pin.vibes.splice(index, 1)
                    console.log(pin.vibes)
                    userAlreadyVibed = true
                } else {
                    console.log('userJustVibed')
                    pin.vibes.push(req.user._id)
                    userAlreadyVibed = false
                }
            })
        }
        let newPin = await Pin.findOneAndUpdate({_id: req.params.pinId}, { vibes: pin.vibes })
        let response = await Pin.findOne({_id: req.params.pinId})
        console.log(response)
        markUpdateTime()
        res.send(response)
    } catch (error) {
        res.send(error)
    }
})

app.delete('/pins/:pinId', passport.authenticate('jwt', {session: false}), async(req, res) => {
    try {
        let pin = await Pin.findOne({_id: req.params.pinId})

        if (pin.by.toString() === req.user._id.toString()) {
            let response = await Pin.deleteOne({ _id: req.params.pinId })
            res.send(response)
            markUpdateTime()
        }

    } catch (error) {
        res.status(404).send(error)
    } 
})

app.get('/users/:username/pins', async (req, res) => {
    try {
        let user = await Users.findOne({ username: req.params.username })
        let pins = await Pin.find( {by: user._id} ).sort('-timestamp')
        res.send(pins)
    } catch (error) {
        res.send(error)
    }
})

app.get('/:pinboard/pins', async (req, res) => {
    try {
        let response = await Pin.find({pinboard: req.params.pinboard}).populate({path: 'by', select: 'username'}).sort('-timestamp').exec()
        res.send(response)
    } catch (error) {
        res.send(error)
    }
})


app.post('/signup', jsonParser, (req, res, next) => {

    let user = {
        email: req.body.email,
        username: req.body.username,
        password: req.body.password,
        realName: req.body.realName
    }

    if(!user.email) {
        return res.status(422).json({
            error: {email: 'is required.'}
        })
    }

    if(!user.password) {
        return res.status(422).json({
            error: {password: 'is required'}
        })
    }

    const finalUser = new Users(user)
    finalUser.setPassword(user.password)

    return finalUser.save().then((res.sendStatus(200)))
    // .then(() => res.json({ user: finalUser.toAuthJSON()}))
})

app.post('/login', jsonParser, function (req, res, next) {

    passport.authenticate('local', {session: false}, function (err, user, info)  {
        if (err || !user) {
            return res.status(400).json({
                message: err,
                user: user
            })
        }

        req.login(user, {session: false}, (err) => {
            if (err) {
                res.status(400).json({
                    message: err
                })
            }

            let userData = {
                id: user._id,
                username: user.username,
                email: user.email
            }

            const token = jwt.sign(userData, 'hugesecret')
            return res.json({userData, token})
        })
    })(req, res)    
})

function markUpdateTime() {
    lastUpdated = Date.now()
} 

app.get('/lastUpdated', (req, res) => {
    // Didn't seem like a good idea to name the route same as I named a global variable
    console.log('hit LASTUPDATED')
    res.json({lastUpdated: updated})
})

const server = app.listen('3000', () => {
    console.log('Živ sam! Slušam na 3000.')
})