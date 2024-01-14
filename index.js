const express = require('express');
const app = express();
const path = require('path');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

mongoose.connect('mongodb://127.0.0.1:27017/backend')
    .then(() => {
        console.log('database connected');
    }).catch((e) => {
        console.log(e);
    });


const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});

const User = mongoose.model('User', userSchema);

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.set('view engine', 'ejs');

const isAuthenticated = async (req, res, next) => {
    const { token } = req.cookies;
    if (token) {
        const decodedData = jwt.verify(token, 'secretkey');
        req.user = await User.findById(decodedData._id);
        next();
    } else {
        res.render('login');
    }
}

app.get('/', isAuthenticated, (req, res) => {
    res.render('logout', {
        name: req.user.name
    });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/login', async (req, res) => {
    let user = await User.findOne({ email: req.body.email });
    if (!user) {
        return res.redirect('/register');
    }


    const isMatch = await bcrypt.compare(req.body.password, user.password);
    if (!isMatch) {
        return res.render('login', {
            message: "Inavalid email or password"
        })
    }

    const token = jwt.sign({ _id: user._id }, 'secretkey');
    res.cookie('token', token, {
        httpOnly: true,
        expires: new Date(Date.now() + 60 * 1000)
    });
    res.redirect('/');
});

app.post('/register', async (req, res) => {

    let user = await User.findOne({ email: req.body.email });
    if (user) {
        return res.redirect('login');
    }
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    user = await User.create({ name: req.body.name, email: req.body.email, password: hashedPassword });
    const token = jwt.sign({ _id: user._id }, 'secretkey');
    res.cookie('token', token, {
        httpOnly: true,
        expires: new Date(Date.now() + 60 * 1000)
    });
    res.redirect('/');
});

app.get('/logout', (req, res) => {
    res.cookie('token', null, {
        httpOnly: true,
        expires: new Date(Date.now())
    });
    res.redirect('/');
});

app.listen(5000, () => {
    console.log('Server is running');
});