const express = require('express')
const bodyParser = require('body-parser')
const pug = require('pug')
const cookieParser = require('cookie-parser')
const session = require('express-session')
const csurf = require('csurf')
const helmet = require('helmet')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const FacebookStrategy = require('passport-facebook').Strategy
const dbUtil = require('./dbUtil')

const PORT = process.env.PORT || 4009
const FACEBOOK_APP_ID = process.env.FACEBOOK_APP_ID
const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET

// ----------- Express -----------
const app = express()
app.use(session({ secret: 'awesome auth', resave: true, saveUninitialized: true }))
app.use(cookieParser())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static('public'))
app.set('view engine', 'pug')


// ----------- Security -----------
const csrf = csurf({ cookie: true })
app.use(helmet())
app.use(csrf)
app.use(function (err, req, res, next) {
	if (err.code !== 'EBADCSRFTOKEN') return next(err)
	res.status(403).render('error', { message: 'Invalid form submission!' })
})


// ----------- Passport -----------
app.use(passport.initialize())
app.use(passport.session())
const passportConfig = { failureRedirect: '/login' }

const authRequired = (req, res, next) => {
	if (req.user) return next()
	else res.redirect('/login?required=1')
}

app.use((req, res, next) => {
	res.locals.user = req.user
	next()
})

passport.use(new LocalStrategy((username, password, done) => {
	dbUtil.getUserByUsername(username)
		.then(async (user) => {
			if (!user) return done('User not found!', false)
			if (!(await dbUtil.isPasswordHashVerified(user.passwd_hash, password))) return done('Invalid Password', false)
			return done(null, user)
		})
		.catch((err) => {
			return done(err)
		})
}))

const fbCallbackUrl = "https://ef66241c.ngrok.io/facebook/callback"
passport.use(new FacebookStrategy({
		clientID: FACEBOOK_APP_ID,
		clientSecret: FACEBOOK_APP_SECRET,
		callbackURL: fbCallbackUrl
	},
	function(accessToken, refreshToken, profile, done) {
		if (accessToken && Object.keys(profile).length > 0) {
			// console.log(accessToken, refreshToken, profile)
			dbUtil.getUserByFbid(profile.id)
				.then(user => {
					done(null, { accessToken, profile, user })
				})
				.catch(err => {
					// console.log('err', err)
					done(err, null)
				})
		}
		else {
			done('FB auth failed!', null)
		}
	}
))

passport.serializeUser((user, cb) => {
	cb(null, user.id)
})

passport.deserializeUser((id, cb) => {
	dbUtil.getUserById(id)
		.then(user => cb(null, user))
		.catch(err => cb(err, null))
})


// ----------- Routes -----------

app.get('/', (req, res) => {
	res.render('index')
})

app.get('/member', authRequired, (req, res) => {
	res.render('member')
})

app.all('/login', (req, res, next) => {
	new Promise((resolve, reject) => {
		if (Object.keys(req.body).length > 0) {
			passport.authenticate('local', (err, user, info) => {
				if (err) {
					reject(err)
				}
				else if (user) {
					resolve(user)
				}
			})(req, res, next)
		}
		else {
			reject()
		}
	})
		.then(user => new Promise((resolve, reject) => {
			req.login(user, err => {
				if (err) return reject(err)
				return res.redirect('/member')
			})
		}))
		.catch(errorMsg => {
			let error = errorMsg
			if (!error && req.query.required) error = 'Authentication required'

			res.render('login', {
				csrfToken: req.csrfToken(),
				error,
				form: req.body,
			})
		})
})

app.all('/register', (req, res) => {
	new Promise(async (resolve, reject) => {
		if (Object.keys(req.body).length > 0) {
			if (
				!(req.body.email && req.body.email.length > 5)
				|| !(req.body.username && req.body.username.length > 1)
				|| !(req.body.password && req.body.password.length > 3)
				|| !(req.body.password2 && req.body.password2.length > 3)
			) {
				reject('Please fill all fields')
			}
			else if (!(
				req.body.email.indexOf('@') !== -1 
				&& req.body.email.indexOf('.') !== -1
			)) {
				reject('Invalid email address')
			}
			else if (req.body.password !== req.body.password2) {
				reject("Password don't match")
			}
			else if (await dbUtil.isUsernameInUse(req.body.username)) {
				reject('Username is taken')
			}
			else if (await dbUtil.isEmailInUse(req.body.email)) {
				reject('Email address is already registered')
			}
			else {
				resolve(true)
			}
		}
		else {
			resolve(false)
		}
	})
		.then(isValidFormData => new Promise((resolve, reject) => {
			if (Object.keys(req.body).length > 0 && isValidFormData) {
				dbUtil.createUserRecord({
					username: req.body.username,
					email: req.body.email,
					password: req.body.password
				})
					.then((creationSuccessful) => {
						console.log('====> user created...')
						console.log(creationSuccessful)
						// authenticate?
						resolve(true)
					})
					.catch(err => reject(err))
			}
			else {
				resolve(false)
			}
		}))
		.then((isRegistrationComplete) => {
			if (isRegistrationComplete) {
				res.render('register-success')
			}
			else {
				res.render('register', {
					csrfToken: req.csrfToken(),
					form: req.body
				})
			}
		})
		.catch((error) => {
			// console.log(error)
			res.render('register', {
				csrfToken: req.csrfToken(),
				error,
				form: req.body
			})
		})
})

app.get('/logout', authRequired, (req, res) => {
	req.logout()
	res.redirect('/')
})

app.get('/auth/facebook', passport.authenticate('facebook'))

app.get('/facebook/callback', (req, res, next) => {
	passport.authenticate('facebook', (err, response) => {
		if (err) {
			// console.log(err)
			res.render('error', { message: err.message })
		}
		// Fb logged in, if user account matched...
		else if (response && response.user) {
			req.login(response.user, err => { // save authentication
				if (err) return res.render('error', { message: err.message })
				return res.redirect('/member')
			})
		}
		// No account, register route...
		else {
			if (req.session.registerAfterFBAuth) {
				dbUtil.createUserRecord({
					fbid: response.profile.id,
					fbtoken: response.accessToken,
				}, true)
					.then((user) => {
						req.login(user, err => { // save authentication
							if (err) return res.render('error', { message: err.message })
							return res.redirect('/member')
						})
						res.redirect('/register-success')
					})
					.catch(e => res.render('error', { message: e.message }))				
			}
			else {
				res.redirect('/register-facebook')
			}
		}
	})(req, res, next)
})

app.get('/register-facebook', (req, res) => {
	res.render('register-facebook')
})

app.get('/register-facebook/confirm', (req, res) => {
	req.session.registerAfterFBAuth = true
	res.redirect('/auth/facebook')
})

// ----------- App start -----------

app.listen(PORT, () => console.log(`App listening on port ${PORT}!`))
