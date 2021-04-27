const express = require('express')
const path = require('path')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const JWT_SECRET = 'sdfsnvlkfjlsvnfdndklnbklnvdsvdvknkldndklvsnknskdndlnlvns'
const app = express()
app.use('/', express.static(path.join(__dirname, 'views')))
app.use(express.json())


//Data base connection
mongoose.connect('mongodb+srv://admin:Krishna@cluster0.0t4mm.mongodb.net/myFirstDatabase?retryWrites=true&w=majority', {
	useNewUrlParser: true,
	useUnifiedTopology: true,
	useCreateIndex: true,
	useFindAndModify:false
})

//change password
app.post('/api/change-password', async (req, res) => {
	const { token, newpassword: textPassword } = req.body
	if (!textPassword || typeof textPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}
	if (textPassword.length < 8) {
		return res.json({
			status: 'error',
			error: 'Password should be atlease 8 char'
		})
	}
	try {
		const user = jwt.verify(token, JWT_SECRET)
		const _id = user.id
		const password =  bcrypt.hash(textPassword, 10)
		await User.updateOne(
			{ _id },
			{
				$set: { password }
			}
		)
		res.json({ status: 'ok' })
	} catch (error) {
		console.log(error)
		return res.json({ status: 'error', error: 'Change Password unsuccesfull' })
	}
})

//Make the login api
app.post('/api/login', async (req, res) => {
	const { username, password } = req.body
	const user = await User.findOneAndUpdate({ username }).lean()

	if (!user) {
		return res.json({ status: 'error', error: 'Invalid username/password' })
	}
	if (bcrypt.compare(password, user.password)) {
		const token = jwt.sign(
			{
				id: user._id,
				username: user.username
			},JWT_SECRET
		)
		return res.json({ status: 'ok', data: token })
	}

	res.json({ status: 'error', error: 'Incorrect username/password' })
})

//Register the user
app.post('/api/register', async (req, res) => {
	const { username, password: textPassword } = req.body
    const password = bcrypt.hash(textPassword, 15)
	if (!username || typeof username !== 'string') {
		return res.json({ status: 'error', error: 'Incorrect username' })
	}
	if (!textPassword || typeof textPassword !== 'string') {
		return res.json({ status: 'error', error: 'Incorrect password' })
	}
	if (textPassword.length < 8) {
		return res.json({
			status: 'error',
			error: 'Need to give atleast 8 alphnumeric char'
		})
	}
	try {
		    const result = await User.create({
		    username,
			password
		})
		console.log("User created", result)
	} catch (error) {
		res.json({ status: 'ok' ,error})
	}
	res.json({ status: 'ok' })
})

app.listen(9000, () => {
	console.log('Node server starting at 9000')
})
