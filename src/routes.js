const express =  require('express');
const Router = express.Router();
const {check, validationResult} = require('express-validator');
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const auth = require('../src/middleware/auth');


Router.get('/users', auth, async(req , res) => {
       try{
        const users = await User.find();
        res.status(200).json(users);
       } catch (error) {
        res.status(500).json({ error: error.message})
       }
    });


Router.post('/register', [

      check('name').notEmpty().withMessage('Name is required'),
      check('email').isEmail().withMessage('Invalid email'),
      check('password').isLength({min: 6}).withMessage('Password must be at laest 6 characters long')

      ], async (req, res) => {

      const errors = validationResult(req);

      if(!errors.isEmpty()){
         return res.status(400).json({ errors: errors.array() });
      }

      const {name, email, password} = req.body;
      try{
        const existingUser = await User.findOne({ email });
        if (existingUser){
            return res.status(400).json({ error: 'Email already in use'});
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword});
        await newUser.save();

        res.status(201).json(newUser);
      } catch (error) {
        res.status(500).json({ error: error.message });
   }
});


Router.post('/login',[
    check('email').isEmail().withMessage('Invalid email'),
    check('password').notEmpty().withMessage('Password is require')
    ], async (req, res) => {
       
        const errors = validationResult(req);

        if(!errors.isEmpty){
            return res.status(400).json({ errors: errors.array() });
        }
       
       const { email, password} = req.body;
       try{

        const user = await User.findOne({ email });
        if(!user) {
            return res.status(400).json({ error: 'Invalid email  or password'});
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid email or password'});
        }

        const token = jwt.sign({ userId: user._id}, process.env.JWT_SECRET, { expiresIn: '1h'});

        res.status(200).json({ token });
    }catch (error) {
        res.status(500).json({ error: error.message});
    }
});

Router.delete('/users/:id', auth, async (req, res) => {
    const { id } = req.params;
    try{
        const user = await User.findByIdAndDelete(id);
        if(!user) {
            return res.status(404).json({ error: 'user not found'});
        }
        res.status(200).json({ message: 'User deleted successfully'});
    } catch  (error){
        res.status(500).json({ error: error.message});
    }
});

module.exports = Router;