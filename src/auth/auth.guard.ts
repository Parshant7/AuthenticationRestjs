import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  HttpException,
  HttpStatus
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { User } from '../users/models/user.model';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

@Injectable()
export class AuthorizeUser implements CanActivate {
  constructor(
    private jwtService: JwtService,
    @InjectModel('users') private User: Model<User>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException();
    }

    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: process.env.secret,
      });

      const user = await this.User.findById(payload._id);
      //checking if user exists in the database;
      if (!user) {
        throw new UnauthorizedException();
      }
      if(!user.isVerified){
        throw new HttpException("email is not verified yet.", HttpStatus.BAD_REQUEST);
      }
      if (payload._id) request['user'] = user;

      request['user'].isResetToken = payload.isResetToken;

    } catch (error) {
      throw new UnauthorizedException();
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}


@Injectable()
export class AuthorizeValidatedUser implements CanActivate {
  constructor(
    private jwtService: JwtService,
    @InjectModel('users') private User: Model<User>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException();
    }

    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: process.env.secret,
      });

      const user = await this.User.findById(payload._id);
      //checking if user exists in the database;
      if (!user) {
        throw new UnauthorizedException();
      }
      if(!user.isVerified){
        throw new HttpException("email is not verified yet.", HttpStatus.BAD_REQUEST);
      }
      if (payload._id) request['user'] = user;

      request['user'].isResetToken = payload.isResetToken;

    } catch (error) {
      throw new UnauthorizedException();
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
