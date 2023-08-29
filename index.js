const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const User = require('./models/User');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const ws = require('ws');
const Message = require('./models/Message');


dotenv.config();


const app = express();
app.use(express.json());
app.use(cookieParser())

console.log(process.env.CLIENT_URL);
app.use(cors({
    credentials: true,
    origin: process.env.CLIENT_URL,
}));
// console.log(process.env.MONGO_URL);
mongoose.connect(process.env.MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log("DB connected");
    })
    .catch(err => {
        console.error("Error connecting to the database:", err);
    });

app.get('/test', (req, res) => {

    res.send("Test ok");
});

app.get('/messages/:userId', async (req, res) => {
    //console.log("Hi from /messages");
    const { userId } = req.params;
    const userData = await getUserDataFromRequest(req);
    const ourUserId = userData.userId;
    const messages = await Message.find({
        sender: { $in: [userId, ourUserId] },
        recipient: { $in: [userId, ourUserId] }
    }).sort({ createdAt: 1 });
    res.json(messages);
})

app.get('/profile', (req, res) => {
    const token = req.cookies?.token;
    if (token) {
        jwt.verify(token, jwtSecret, {}, (err, userData) => {
            if (err) throw err;
            const { id, username } = userData;
            res.json(userData);
        });
    } else {
        // res.status(401).json('no token');
        res.send("Shi pakde hai");
        console.log("Hi")
    }
});

async function getUserDataFromRequest(req) {
    return new Promise((resolve, reject) => {
        const token = req.cookies?.token;
        if (token) {
            jwt.verify(token, jwtSecret, {}, (err, userData) => {
                if (err) throw err;
                // res.json(userData);
                resolve(userData);
            });
        }
        else {
            reject('no token');
        }
    });
}

const jwtSecret = process.env.JWT_SECRET;
const bcryptSalt = bcrypt.genSaltSync(10);

app.post('/register', async (req, res) => {
    console.log("Hi from register");
    const { username, password } = req.body;
    try {
        const hashedPassword = bcrypt.hashSync(password, bcryptSalt);
        const createdUser = await User.create({
            username: username,
            password: hashedPassword,
        });
        jwt.sign({ userId: createdUser._id, username }, jwtSecret, {}, (err, token) => {
            if (err) throw err;
            res.cookie('token', token, { sameSite: 'none', secure: true }).status(201).json({
                id: createdUser._id,
            });
        });
    }
    catch (err) {
        //This directly closes our server if  duplicate entry with same username and password if found. Handle it!!
        if (err) throw err;
        res.status(500).json('error');
    }

});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const foundUser = await User.findOne({ username });
    if (foundUser) {
        const passOk = bcrypt.compareSync(password, foundUser.password);
        if (passOk) {
            jwt.sign({ userId: foundUser._id, username }, jwtSecret, {}, (err, token) => {
                if (err) throw err;
                res.cookie('token', token, { sameSite: 'none', secure: true }).json({
                    id: foundUser._id,
                });
            });
        }
    }
});


const server = app.listen(4040);
//---------------------------------Socket--------------------------
//handling web sockets
//wss :web socket server 
const wss = new ws.WebSocketServer({ server });
wss.on('connection', (connection, req) => {
    //for finding who're online
    // console.log(req.headers);
    //Reading info from cookie
    const cookieInfo = req.headers.cookie;
    if (cookieInfo) {
        const tokenCookieString = cookieInfo.split(';').find(str => str.startsWith('token='));
        if (tokenCookieString) {
            const token = tokenCookieString.split('=')[1];
            if (token) {    // console.log(token);
                //decoding data from token 
                jwt.verify(token, jwtSecret, {}, (err, userData) => {
                    if (err)
                        throw err;
                    // console.log(userData);
                    //username i/p . Stored in connection.userName
                    const { userId, username } = userData;
                    //adding custom property to connection 
                    //So, that i can be used later to find who're online and rest stuff!!
                    //than all this will be stored in wss server
                    connection.userId = userId;
                    connection.userName = username;
                });
            }
        }
    }

    //Always triggers when data is received from client
    connection.on('message', async (message) => {
        const messageData = JSON.parse(message.toString());

        // const { recipient,SenderPublicKey,text } = messageData;
        const { recipient,text } = messageData;
        // const { recipient, SenderPublicKey } = messageData;
        
        //console.log(SenderPublicKey);
        // console.log('rcpt', recipient);
        // console.log('txt', text);
        // if (SenderPublicKey) {
        //     console.log("AUTHENTICATION REQUEST SENDING");
        //     [...wss.clients]
        //         .filter(c => c.userId === recipient)
        //         .forEach(c => c.send(JSON.stringify({
        //             auth: 1,
        //             sender: connection.userId,
        //             recipient,
        //             SenderPublicKey
        //         })));//need text as well as sender also for ui purpose in chat
        // }
        if (recipient && text) {
            //storing in db 
            const MessageDoc = await Message.create({
                sender: connection.userId,
                recipient,
                text,
            });
            //.filter is better than .find because let say user is login in multiple devices
            //Than I need to send data to all devices
            //But find would find for single match
            [...wss.clients]
                .filter(c => c.userId === recipient)
                .forEach(c => c.send(JSON.stringify({
                    text,
                    sender: connection.userId,
                    recipient,
                    //sending id from Db to avoid re-appearence of message due to event listerner
                    _id: MessageDoc._id,
                })));//need text as well as sender also for ui purpose in chat

            //console.log('received from client');
            // console.log({text});

        }

    });

    //transforming to array
    //.clients predefined property that stores all users at-the-moment connected
    // console.log([...wss.clients].map(c=>c.userName));
    //notify everyone about new Connection
    [...wss.clients].forEach(client => {
        client.send(JSON.stringify({
            online: [...wss.clients].map(c => ({ userId: c.userId, username: c.userName }))
        }));
    });
});
