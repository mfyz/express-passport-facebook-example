const { Pool } = require('pg')
const argon2 = require('argon2')

const pool = new Pool({
	connectionString: process.env.DATABASE_URL,
	ssl: true
})

let connection = null

const getConnection = async () => {
	try {
		if (connection === null) {
			connection = await pool.connect()
			// console.log('------->>> Connection successful!')
		}
	}
	catch (e) {
		console.log('-----> DB connection error!', e)
	}
	return connection
}

const disconect = () => {
	try {
		return connection.release()
	}
	catch (e) {
		return false
	}
}

const runQuery = (query, values) => new Promise((resolve, reject) => {
	let queryObj = null
	if (values) queryObj = { text: query, values }
	else queryObj = query
	// console.log(queryObj)
	getConnection().then((conn) => {
		conn.query(queryObj, (err, res) => {
			// console.log('=======> query ' + (err ? 'error':'result') +':', query, (err ? err : res));
			if (err) reject(err)
			else resolve(res)
		})
	})
})

const getUserById = id => new Promise((resolve, reject) => {
	runQuery(`SELECT * FROM users WHERE id = $1`, [id])
		.then((result) => {
			if (result.rowCount === 0) resolve(null)
			else resolve(result.rows[0])
		})
		.catch(err => reject(err))
})

const getUserByUsername = username => new Promise((resolve, reject) => {
	runQuery(`SELECT * FROM users WHERE username = $1`, [username])
		.then((result) => {
			if (result.rowCount === 0) resolve(null)
			else resolve(result.rows[0])
		})
		.catch(err => reject(err))
})

const getUserByEmail = email => new Promise((resolve, reject) => {
	runQuery(`SELECT * FROM users WHERE email = $1`, [email])
		.then((result) => {
			if (result.rowCount === 0) resolve(null)
			else resolve(result.rows[0])
		})
		.catch(err => reject(err))
})

const isUsernameInUse = async username => {
	return await getUserByUsername(username) !== null
}

const isEmailInUse = async email => {
	return (await getUserByEmail(email) ? true : false)
}

const createUserRecord = userObj => new Promise(async (resolve, reject) => {
	const passwdHash = await createPasswordHash(userObj.password)
	runQuery(
		`INSERT INTO users (email, username, passwd_hash, createdAt) VALUES ($1, $2, $3, NOW())`,
		[userObj.email, userObj.username, passwdHash]
	)
		.then((result) => {
			if (result.rowCount === 1) resolve(true)
			else resolve(false)
		})
		.catch((err) => {
			reject(err)
		})
})

const createPasswordHash = (password) => new Promise(async (resolve, reject) => {
	try {
		const hash = await argon2.hash(password)
		resolve(hash)
	} catch (err) {
		reject(err)
	}
})

const isPasswordHashVerified = (hash, password) => new Promise(async (resolve, reject) => {
	try {
		if (await argon2.verify(hash, password)) {
			resolve(true)
		}
		else {
			resolve(false)
		}
	} catch (err) {
		reject(err)
	}
})

module.exports = {
	getConnection,
	disconect,
	getUserById,
	getUserByUsername,
	getUserByEmail,
	isUsernameInUse,
	isEmailInUse,
	createUserRecord,
	isPasswordHashVerified,
}
