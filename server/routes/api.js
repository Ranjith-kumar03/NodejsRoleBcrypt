const express = require('express')
const jwt = require('jsonwebtoken')
const router = express.Router()
const User = require('../models/user')
const Event = require('../models/event')
const PORT = 3000
const  mongoose = require('mongoose')
const accessTokenSecret = 'youraccesstokensecret';

const refreshTokenSecret = 'yourrefreshtokensecrethere';
const refreshTokens = [];
const bcrypt = require('bcryptjs')

const uri = 'mongodb://localhost:27017/AuthorizationDatabase'
let currentUser =''

mongoose.connect(uri, {  useNewUrlParser: true ,useUnifiedTopology: true })
    .then(db => {
        // boot

            console.log("DB Listening on port: ", PORT);

    })
    .catch(dbErr => {
        console.log("DB Connection Error: ", dbErr.message);
        //process.exit(1);
    });

///Verify Token
const authenticateJWT = (req, res, next) => {
    if(!req.headers.authorization)
    {
        return res.status(401).send('UnAuthorized Request')
    }

    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(' ')[1];
        if(token === 'null')
        {
            return res.status(401).send('UnAuthorized Request')
        }

       let payload = jwt.verify(token, accessTokenSecret, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }

            req.user = user;
            console.log("Iam from verify token")
            console.log(req.user)
            next();
        });
    } else {
        res.sendStatus(401);
    }
};




router.get('/' , (req, res)=>{
    res.send('from PI route')
})

router.post('/register' , async (req,res)=>{

    let userData = req.body
    let user = new User(userData)
    const salt = await bcrypt.genSalt()
    const hashPassword  = await bcrypt.hash(user.password,salt)
    user.password = hashPassword
    console.log(user.password)
    console.log(user)

    user.save((err, regUser) => {
        if (err) {
            console.log(err)
        } else {
             // filter user froem Database
            //const user = users.find(u => { return u.username === username && u.password === password });
            User.findOne({email: userData.email}, (err, user) => {

                if (err) {
                    console.log(err)

                } else {


                    if (!user) {
                        res.status(401).send('Invalid Email')
                    } else {
                        if (user) {
                            // generate an access token
                            const accessToken = jwt.sign({userID: user._id, username: user.username,roles: user.roles }, accessTokenSecret, {expiresIn: '20m'});
                            const refreshToken = jwt.sign({userID: user._id, username: user.username,roles: user.roles}, refreshTokenSecret);

                            refreshTokens.push(refreshToken);

                            res.json({
                                accessToken,
                                refreshToken ,roles:user.roles
                            });
                        } else {
                            res.send('Username or password incorrect');
                        }

                       // res.status(200).send(regUser)
                    }
                }


            })

        }

    });


})


router.post('/login',async (req,res)=>{
    let userData = req.body
    User.findOne({email: userData.email},(err, user)=>{
        console.log(userData.password)
        console.log(user.password)
console.log(user)
        if(err){
            console.log(err)

        }else{


            if(!user)
            {
                res.status(401).send('Invalid Email')
            }else if(bcrypt.compareSync(userData.password,user.password))// userData.password !== user.password
            {
                if (user) {
                    // Check for Admin
                    currentUser = user
                    if(user.roles==='ADMIN'){
                        console.log("Can do ADMIN activities")
                    }else
                    {
                        console.log('cannot do admon activities')
                    }
                    // generate an access token
                    const accessToken = jwt.sign({userID: user._id, username: user.username,roles: user.roles }, accessTokenSecret, {expiresIn: '20m'});
                    const refreshToken = jwt.sign({userID: user._id, username: user.username,roles: user.roles}, refreshTokenSecret);

                    refreshTokens.push(refreshToken);

                    res.json({
                        accessToken,
                        refreshToken, roles:user.roles
                    });
                } else {
                    res.send('Cant Generate Token');
                }
                
            }else
            {
                
                res.status(401).send('password not matches')



            }
        }
    })
})

router.post('/events' , (req , res) => {
 const role = currentUser.roles
   let eventNew = req.body
   eventNew.date = new Date().toISOString()
   let event = new Event(eventNew)
    //console.log(currentUser)
    if (currentUser.roles !== 'ADMIN') {

        return res.status(403).send("Not an Admin")

    }else{

       event.save((err, events) =>{
           if(err)
           {
               console.log(err)
           }else
           {

               res.status(200).send({events})
           }


        })

    }

})



router.get('/events', (req , res)=>{
    return Event.find( {},(err, data) => {
        if(err){
            console.log(err);
            return
        }

        if(data.length == 0) {
            console.log("No record found")
            return
        }

        res.status(200).send(data)
    })
})

router.get('/special', authenticateJWT,  (req, res) => {

    let specialEvents = [
        {
            "_id": "1",
            "name": "Auto Expo Special",
            "description": "lorem ipsum",
            "date": "2012-04-23T18:25:43.511Z"
        },
        {
            "_id": "2",
            "name": "Auto Expo Special",
            "description": "lorem ipsum",
            "date": "2012-04-23T18:25:43.511Z"
        },
        {
            "_id": "3",
            "name": "Auto Expo Special",
            "description": "lorem ipsum",
            "date": "2012-04-23T18:25:43.511Z"
        },
        {
            "_id": "4",
            "name": "Auto Expo Special",
            "description": "lorem ipsum",
            "date": "2012-04-23T18:25:43.511Z"
        },
        {
            "_id": "5",
            "name": "Auto Expo Special",
            "description": "lorem ipsum",
            "date": "2012-04-23T18:25:43.511Z"
        },
        {
            "_id": "6",
            "name": "Auto Expo Special",
            "description": "lorem ipsum",
            "date": "2012-04-23T18:25:43.511Z"
        }
    ]
    res.json(specialEvents)
})

router.delete('/event/:id', authenticateJWT, (req , res)=>{
    console.log(req.user.roles + "status")
    if (req.user.roles === 'ADMIN') {
        var uid = req.params.id.toString();
        //console.log(uid)
        Event.deleteOne({"_id": uid}, (err, result) => {
            if (err) {
                console.log(err);

            }
            if (result) {
                return Event.find({}, (err, data) => {
                    if (err) {
                        console.log(err);
                        return
                    }

                    if (data.length == 0) {
                        console.log("No record found")
                        return
                    }

                    res.status(200).send(data )
                })

            }

        });
    }else
    {
        res.status(401).send("Unauthorized")
    }
})

////////////////////////////////Refresh Token Yet To Study////////////////////////////////
router.post('/token', (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.sendStatus(401);
    }

    if (!refreshTokens.includes(token)) {
        return res.sendStatus(403);
    }

    jwt.verify(token, refreshTokenSecret, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }

        const accessToken = jwt.sign({ username: user.username, role: user.role }, accessTokenSecret, { expiresIn: '20m' });

        res.json({
            accessToken
        });
    });
});





module.exports = router