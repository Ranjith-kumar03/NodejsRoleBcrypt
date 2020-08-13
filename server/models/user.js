const mongoose = require('mongoose')

const schema = mongoose.Schema

const userSchema = new schema({

    email : {type: String , required: true },
    password : {type: String , required: true},
    roles : {type: String, required: true , default: 'USER'}


})

module.exports = mongoose.model('User' , userSchema)