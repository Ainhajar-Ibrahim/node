const express = require('express');
const app = express();
const http = require('http');
const bodyParser = require('body-parser')
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server);
var path = require('path');
const mongoose= require('mongoose');
const dbURI= 'mongodb+srv://ibrahim:ainhajar@cluster0.xc58x.mongodb.net/sharidb?retryWrites=true&w=majority';
const User = require('./model/user');
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const JWT_SECRET = 'sdjkfh8923yhjdksbfma@#(&@!^#&@bhjb2qiuhesdbhjdsfg839ujkdhfjk'


mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(result => {
    console.log('connected to db');
  })
  .catch(err => console.log(err));


app.use(bodyParser.json());

app.post('/public/register', async (req, res) => { console.log(req.body)
    res.json({status:'ok'});})

 
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.use(express.static(path.join(__dirname, 'public')));


app.get('/about', (req, res) => {
  res.sendFile(__dirname + '/public/about.html');
}
);

app.get('/register', (req, res) => {
  res.sendFile(__dirname + '/public/register.html');
}
);

app.post('/api/change-password', async (req, res) => {
	const { token, newpassword: plainTextPassword } = req.body

	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}

	if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 6 characters'
		})
	}

	try {
		const user = jwt.verify(token, JWT_SECRET)

		const _id = user.id;

		const password = await bcrypt.hash(plainTextPassword, 10)

		await User.updateOne(
			{ _id },
			{
				$set: { password }
			}
		)
		res.json({ status: 'ok' })
	} catch (error) {
		console.log(error)
		res.json({ status: 'error', error: ';))' })
	}
})

app.get('/api/profile', async (req, res) => {
	const  token  = req.get('token');
	

	try {
		const user = jwt.verify(token, JWT_SECRET)
		const name1 = user.username
		const user1 = await User.findOne( {username:name1  }).lean()
		res.json({ username: user1.username, email: user1.email, phone: user1.phone })
		console.log(user1.username)
	} catch (error) {
		console.log(error)
		res.json({ status: 'error', error: 'no account found' })
	}
})

app.post('/api/login', async (req, res) => {
	const { username, password } = req.body
	const user = await User.findOne({ username }).lean()

	if (!user) {
		return res.json({ status: 'error', error: 'Invalid username/password' })
	}

	if (await bcrypt.compare(password, user.password)) {
		// the username, password combination is successful

		const token = jwt.sign(
			{
				id: user._id,
				username: user.username
			},
			JWT_SECRET
		)

		return res.json({ status: 'ok', data: token })
	}

	res.json({ status: 'error', error: 'Invalid username/password' })
})

app.post('/api/register', async (req, res) => {
	const { username, password: plainTextPassword, email, phone } = req.body

	if (!username || typeof username !== 'string') {
		return res.json({ status: 'error', error: 'Invalid username' })
	}

	if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}

	if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 6 characters'
		})
	}

	const password = await bcrypt.hash(plainTextPassword, 10)

	try {
		const response = await User.create({
			username,
			password,
			email,
			phone
		})
		console.log('User created successfully: ', response)
	} catch (error) {
		if (error.code === 11000) {
			// duplicate key
			return res.json({ status: 'error', error: 'Username already in use' })
		}
		throw error
	}

	res.json({ status: 'ok' })
})


io.on('connection', (socket) => {
    console.log('a user connected');
    socket.on('disconnect', () => {
      console.log('user disconnected');
    });
    socket.on('chat login',() => {
        console.log('visited index');
      });
      socket.on('chat about',() => {
        console.log('visited about');
      });  
	  socket.on('chat register',() => {
        console.log('visited register');
      });
	  socket.on('chat profiles',() => {
        console.log('visited profile');
      });
  });
  
server.listen(3000, () => {
  console.log('listening on *:3000');
});