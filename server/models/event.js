const mongoose = require('mongoose')

const schema = mongoose.Schema

const userSchema = new schema({

    name : {type: String , required: true },
    description : {type: String , required: true},
    date :{type: String , required: true}
// new Date().toISOString()

})

module.exports = mongoose.model('Event' , userSchema)


