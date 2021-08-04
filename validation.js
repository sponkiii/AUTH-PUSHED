// Validation
const Joi = require('@hapi/joi');

// Register Validation 
const registerValidation = (data) => {
    //sample schema with joi
    const schema = Joi.object(
        {
            name: Joi.string()
                .min(6)
                .required(),
            email: Joi.string()
                .min(6)
                .required()
                .email(),
            password: Joi.string()
                .required()
                .min(6)
        }
    );
    // parameters are the body where we get the data and the schema that we made
    //it's an object so we can actually store it as an object
    return schema.validate(data);

    
};
// Login Validation 
const loginValidation = (data) => {
    //sample schema with joi
    const schema = Joi.object(
        {
            email: Joi.string()
                .min(6)
                .required()
                .email(),
            password: Joi.string()
                .required()
                .min(6)
        }
    );
    return schema.validate(data);

    
};

module.exports.registerValidation = registerValidation;
module.exports.loginValidation = loginValidation;