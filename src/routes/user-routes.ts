import {Router} from 'express'
import { getAllUsers, userLogin, userSignup, forgotPassword,resetPassword, updatePassword } from '../controllers/user-controllers.js';
import user from '../models/User.js';
import { loginValidator, signupValidator, validate } from '../utils/validators.js';

const userRoutes = Router();

userRoutes.get('/', getAllUsers);
userRoutes.post('/signup', validate(signupValidator), userSignup);
userRoutes.post('/login', validate(loginValidator), userLogin);
userRoutes.post('/forgotPassword', forgotPassword);
userRoutes.patch('/resetPassword/:token', resetPassword);
userRoutes.patch('/updatePassword', updatePassword);



export default userRoutes;
