import {
  Injectable,
  UnauthorizedException,
  HttpException,
  HttpStatus,
  BadRequestException
} from '@nestjs/common';
import {Request as RequestExpress } from "express";
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
// import { UserSchema } from './schemas/user.schema';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './models/user.model';
import { Otp } from './models/otp.model';
import { LoginUserDto } from './dto/login-user.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { MailerService } from '@nestjs-modules/mailer';
import { otpGen } from 'otp-gen-agent';
import * as moment from 'moment';
import { ChangePasswordDto } from "./dto/change-password.dto";
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdateEmailDto } from './dto/update-email.dto';
import { OtpDto } from './dto/otp.dto';

const saltOrRounds = 10;

@Injectable()
// @Dependencies('User') // this line causes error while using jwt.signAsync
export class UsersService {
  constructor(
    @InjectModel('users') private User: Model<User>,
    @InjectModel('otps') private Otp: Model<Otp>,

    private readonly mailerService: MailerService,
    private readonly jwtService: JwtService,
  ) {}

  async register(newUser: CreateUserDto): Promise<User> {
    const isExists = (await this.findOne(newUser.email)) ? true : false;

    if (isExists) {
      throw new HttpException(
        `Email '${newUser.email}' already exists.`,
        HttpStatus.CONFLICT,
      );
    }

    newUser.password = await bcrypt.hash(newUser.password, saltOrRounds);
    await this.sendOtp(newUser);
    const createdUser = await this.User.create(newUser);
    return createdUser;
  }

  async login(userCredentials: LoginUserDto): Promise<any> {
    const user = await this.User.findOne({ email: userCredentials.email });
    
    if(!user){
      throw new UnauthorizedException();
    }

    const isMatch = await bcrypt.compare(
      userCredentials.password,
      user.password,
    );

    if (!isMatch) {
      throw new UnauthorizedException();
    }
    const payload = { _id: user._id, email: user.email };

    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }

  async findOne(email: string): Promise<any> {
    console.log('email i got ', email);
    return await this.User.findOne({ email: email });
  }

  async verifyEmail(req: RequestExpress): Promise<any> {
    //validating otp
    const userId = req["user"]._id;
    const user = await this.User.findById(userId).populate("otp");
    
    await this.verifyOtp(req, user);

    // if in user isVerified is false then turn it to true 
    if(!user.isVerified){
      await this.User.findByIdAndUpdate(userId, {isVerified: true});
      return "email is successfully verified";
    }
    return "otp is successfully verified";
  }


  async verifyOtp(req: RequestExpress, user: CreateUserDto): Promise<any>{

    const otpRecieved = req.body.otp;
    console.log("this is the otp i recieved ", otpRecieved);

    if(!user){
      throw new UnauthorizedException('user does not exists');
    }

    if(!otpRecieved){
      throw new BadRequestException('OTP not received in the request body');
    }

    console.log("this is user ", user);
    //get reference of otp
    const otpDoc = user.otp;
    
    // checking if otp already used;
    if(otpDoc.isVerified){
      throw new BadRequestException('Invalid otp');
    }

    // checking if otp expired
    if(moment(otpDoc.expiryDate).isBefore(moment())){
      throw new BadRequestException('Otp expired');
    }

    if (otpRecieved != otpDoc.pin){
      throw new BadRequestException('Invalid otp');
    }

    //otp is correct and verified----------------------------
    
    // otpDoc.isVerified = true;
    await this.Otp.findByIdAndUpdate(otpDoc._id, {isVerified: true});
  }

  async refreshOtp(req: RequestExpress): Promise<string> {
    const userId = req["user"]._id;
    const user = await this.User.findById(userId).populate("otp");
    const otpId = user.otp._id;

    await this.sendOtp(user, otpId);
    return "otp sent to your email " + user.email;
  }

  async sendOtp(user: CreateUserDto, otpId: string|null = null, newEmail: string|null = null){
    const randomPin = await otpGen();

    this.mailerService.sendMail({
      to: newEmail? newEmail:user.email,
      from: 'laisha.erdman35@ethereal.email',
      subject: 'Testing Nest MailerModule',
      text: randomPin,
      html: `<b>${randomPin}<b>`,
    });
    //--------------

    //update the whole object of otp
    const newOtp = {
      pin: randomPin,
      createdAt: moment(),
      expiryDate: moment().add(1, 'h'),
      email: newEmail? newEmail:user.email,
      isVerified: false
    };

    if(otpId){
      await this.Otp.findByIdAndUpdate(otpId, newOtp);
    }else{
      const otpDoc = await this.Otp.create(newOtp);
      user.otp = otpDoc._id;
    }
  }

  async changePassword(req: RequestExpress, body: ChangePasswordDto): Promise<any>{
    
    const newPassword = body.newPassword;
    const currentPassword = body.currentPassword;

    console.log("this is user ", req["user"]);
    console.log(" this is hashed password ",await bcrypt.hash(currentPassword, saltOrRounds));

    if(! await bcrypt.compare(currentPassword, req["user"].password)){
      throw new UnauthorizedException('Incorrect current password');
    }

    await this.User.findByIdAndUpdate(req["user"]._id, {
      password:  await bcrypt.hash(newPassword, saltOrRounds)
    });

    return {
      message: "successfully changed the password"
    }
  }

  async forgotPassword(req: RequestExpress, body: ForgotPasswordDto): Promise<any>{
    const email = body.email;
    if(email !== req["user"].email){
      throw new UnauthorizedException('invalid email');
    }
    const user = await this.User.findOne({email: email}).populate("otp");

    if(!user){
      throw new UnauthorizedException('User does not exists');
    }
    
    await this.sendOtp(user, user.otp._id);
    
    const payload = { _id: user._id, email: user.email, isResetToken: true };
    return {
      access_token: await this.jwtService.signAsync(payload, {expiresIn: '2m'}),
    };

  }

  async resetPassword(req: RequestExpress, body: ResetPasswordDto): Promise<any>{

    const userId = req["user"]._id;
    console.log("this is user", req["user"]);
    if(!req["user"].isResetToken){
      throw new HttpException('Invalid token', HttpStatus.BAD_REQUEST);
    }

    const user = await this.User.findById(userId).populate("otp");

    if(body.newPassword !== body.confirmPassword){
      throw new HttpException('Passwords do not match', HttpStatus.BAD_REQUEST);
    }

    await this.verifyOtp(req, user);


    await this.User.findByIdAndUpdate(userId, {
      password: await bcrypt.hash(body.newPassword, saltOrRounds)
    })

    return "Password reset Successfully";
  }

  async emailUpdateRequest(req: RequestExpress, body: UpdateEmailDto): Promise<any>{

    const userId = req["user"]._id;
    const newEmail = body.newEmail;
    
    let user = await this.User.findOne({email: newEmail});

    if(user){
      throw new HttpException('Email already exists', HttpStatus.BAD_REQUEST);
    }

    console.log("this is user", req["user"]);

    // if(!req["user"].isResetToken){
    //   throw new HttpException('Invalid token', HttpStatus.BAD_REQUEST);
    // }

    user = await this.User.findById(userId).populate("otp");

    await this.sendOtp(user, user?.otp._id, newEmail);

    return "Otp sent Successfully";
  }


  async emailUpdate(req: RequestExpress, body: OtpDto): Promise<any>{

    const userId = req["user"]._id;
    // const newEmail = body.newEmail;
    
    let user = await this.User.findById(userId).populate("otp");


    // if(user){
    //   throw new HttpException('Email already exists', HttpStatus.BAD_REQUEST);
    // }

    /////////////////////////

    await this.verifyOtp(req, user);

    /////////////////////////

    console.log("this is user", req["user"]);

    // if(!req["user"].isResetToken){
    //   throw new HttpException('Invalid token', HttpStatus.BAD_REQUEST);
    // }

    await this.User.findByIdAndUpdate(userId, {email: user.otp.email});

    return "successfully changed the email";
  }

}
