import {
  Injectable,
  UnauthorizedException,
  HttpException,
  HttpStatus,
  BadRequestException,
  Inject,
} from '@nestjs/common';
import { Request as RequestExpress } from 'express';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { MailerService } from '@nestjs-modules/mailer';
import { otpGen } from 'otp-gen-agent';
import * as moment from 'moment';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdateEmailDto } from './dto/update-email.dto';
import { OtpDto } from './dto/otp.dto';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import { Otp } from './otp.entity';

const saltOrRounds = 10;

@Injectable()
export class UsersService {
  constructor(
    @Inject('USER_REPOSITORY')
    private userRepository: Repository<User>,
    @Inject('OTP_REPOSITORY')
    private otpRepository: Repository<Otp>,
    private readonly mailerService: MailerService,
    private readonly jwtService: JwtService,
  ) {}

  async findAll(): Promise<User[]> {
    return this.userRepository.find();
  }

  // REGISTER NEW USERS -----------------
  async register(newUser: CreateUserDto): Promise<User> {
    const isExists = !!(await this.userRepository.findOne({
      where: { email: newUser.email },
    }));
    //if email already exists
    if (isExists) {
      throw new HttpException(
        `Email '${newUser.email}' already exists.`,
        HttpStatus.CONFLICT,
      );
    }
    newUser.password = await bcrypt.hash(newUser.password, saltOrRounds);
    //sending the otp to the user;
    await this.sendOtp(newUser);
    //save the user
    const createdUser = await this.userRepository.save(newUser);
    return createdUser;
  }

  async login(userCredentials: LoginUserDto): Promise<any> {
    const user = await this.userRepository.findOne({
      where: { email: userCredentials.email },
    });

    if (!user) {
      throw new UnauthorizedException();
    }

    const isMatch = await bcrypt.compare(
      userCredentials.password,
      user.password,
    );

    if (!isMatch) {
      throw new UnauthorizedException();
    }

    const payload = { id: user.id, email: user.email };

    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }

  async verifyEmail(req: RequestExpress): Promise<any> {
    //validating otp
    const userId = req['user'].id;
    const user = await this.userRepository.findOneBy({ id: userId });

    console.log('user', user);
    await this.verifyOtp(req, user);

    // if in user isVerified is false then turn it to true
    if (!user.isVerified) {
      await this.userRepository.update(userId, { isVerified: true });
      return 'email is successfully verified';
    }
    return 'otp is successfully verified';
  }

  async verifyOtp(req: RequestExpress, user: CreateUserDto): Promise<any> {
    const otpRecieved = req.body.otp;
    console.log('otp recieved ', otpRecieved);

    if (!user) {
      throw new UnauthorizedException('user does not exists');
    }

    if (!otpRecieved) {
      throw new BadRequestException('OTP not received');
    }

    console.log('this is user ', user);

    //get reference of otp
    const otpDoc = user.otp;

    // checking if otp already used or wrong pin provided;
    if (otpDoc?.isVerified || otpRecieved != otpDoc?.pin) {
      throw new BadRequestException('Invalid otp');
    }

    // checking if otp expired
    if (moment(otpDoc.expiryDate).isBefore(moment())) {
      throw new BadRequestException('Otp expired');
    }

    //here otp is correct and verified
    await this.otpRepository.update(otpDoc.id, { isVerified: true });
  }

  // REFRESH OTP
  async refreshOtp(req: RequestExpress): Promise<string> {
    const userId = req["user"].id;
    const user = await this.userRepository.findOneBy({id: userId});
    const otpId = user.otp?.id;

    await this.sendOtp(user, otpId);
    return "otp sent to your email " + user.email;
  }

  // SEND OTP TO THE USER, OTP reference and NewEmail are optional
  async sendOtp(
    user: CreateUserDto,
    otpId: number | null = null,
    newEmail: string | null = null,
  ) {
    const randomPin = await otpGen();

    //send the mail to the user's email
    this.mailerService.sendMail({
      to: newEmail ? newEmail : user.email,
      from: 'laisha.erdman35@ethereal.email',
      subject: 'Testing Nest MailerModule',
      text: randomPin,
      html: `<b>${randomPin}<b>`,
    });

    //update the whole object of otp
    const newOtp = {
      pin: randomPin,
      createdAt: moment().toDate(),
      expiryDate: moment().add(1, 'h').toDate(),
      email: newEmail ? newEmail : user.email,
      isVerified: false,
    };

    console.log('user reached here ', user);
    if (otpId) {
      console.log('otp id received', otpId);
      await this.otpRepository.update(otpId, newOtp);
    } else {
      console.log('newopt row ', newOtp);
      const otpDoc = await this.otpRepository.save(newOtp);
      user.otp = otpDoc.id;
    }
  }

  async changePassword(
    req: RequestExpress,
    body: ChangePasswordDto,
  ): Promise<any> {
    const newPassword = body.newPassword;
    const currentPassword = body.currentPassword;

    console.log('this is user ', req['user']);

    if (!(await bcrypt.compare(currentPassword, req['user'].password))) {
      throw new UnauthorizedException('Incorrect current password');
    }

    await this.userRepository.update(req['user'].id, {
      password: await bcrypt.hash(newPassword, saltOrRounds),
    });

    return {
      message: 'successfully changed the password',
    };
  }

  async forgotPassword(
    req: RequestExpress,
    body: ForgotPasswordDto,
  ): Promise<any> {
    const email = body.email;
    if (!email) {
      throw new UnauthorizedException('email not received');
    }

    const user = await this.userRepository.findOneBy({ email: email });

    if (!user) {
      throw new UnauthorizedException('No user exists with this email');
    }

    await this.sendOtp(user, user.otp.id);

    const payload = { id: user.id, email: user.email, isResetToken: true };
    return {
      access_token: await this.jwtService.signAsync(payload, {
        expiresIn: '2m',
      }),
    };
  }

  async resetPassword(
    req: RequestExpress,
    body: ResetPasswordDto,
  ): Promise<any> {
    const userId = req['user'].id;
    console.log('this is user', req['user']);

    if (!req['user'].isResetToken) {
      throw new HttpException('Invalid token', HttpStatus.BAD_REQUEST);
    }

    const user = await this.userRepository.findOneBy({ id: userId });

    if (body.newPassword !== body.confirmPassword) {
      throw new HttpException('Passwords do not match', HttpStatus.BAD_REQUEST);
    }

    await this.verifyOtp(req, user);

    await this.userRepository.update(userId, {
      password: await bcrypt.hash(body.newPassword, saltOrRounds),
    });

    return 'Password reset Successfully';
  }

  async emailUpdateRequest(
    req: RequestExpress,
    body: UpdateEmailDto,
  ): Promise<any> {
    const userId = req['user'].id;
    const newEmail = body.newEmail;

    let user = await this.userRepository.findOneBy({ email: newEmail });

    // check if email already exists
    if (user) {
      throw new HttpException('Email already exists', HttpStatus.BAD_REQUEST);
    }

    console.log('this is user', req['user']);

    user = await this.userRepository.findOneBy({ id: userId });

    await this.sendOtp(user, user?.otp.id, newEmail);

    return 'Otp sent Successfully';
  }

  async emailUpdate(req: RequestExpress, body: OtpDto): Promise<any> {
    console.log(body);
    const userId = req['user'].id;
    // const newEmail = body.newEmail;

    const user = await this.userRepository.findOneBy({ id: userId });

    await this.verifyOtp(req, user);

    console.log('this is user', req['user']);

    await this.userRepository.update(userId, { email: user.otp.email });

    return 'successfully changed the email';
  }
}
