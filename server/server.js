const express = require('express')
const bodyparser = require('body-parser')
const cors = require('cors')
const api = require('./routes/api')

const PORT = 3000
const app = express()
app.use(bodyparser.json())
app.use(cors())


app.use('/api', api);

app.get('/' , (req , res) =>{
    res.send('hello from server')
})

app.listen(PORT , (req , res) =>{
    console.log('Server Running on Port -' + PORT)
})