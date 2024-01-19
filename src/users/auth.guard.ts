import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  HttpException,
  HttpStatus,
  Inject
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { User } from './models/user.model';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Repository } from 'typeorm';

@Injectable()
export class AuthorizeUser implements CanActivate {
  constructor(
    private jwtService: JwtService,
    @Inject('USER_REPOSITORY')
    private userRepository: Repository<User>,
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

      console.log("payload received ", payload);
      const user = await this.userRepository.findOneBy({id: payload.id});
      console.log("authorize user", user);
      //checking if user exists in the database;
      if (!user) {
        throw new UnauthorizedException();
      }

      if (payload.id) request['user'] = user;

      request['user'].isResetToken = payload.isResetToken;

    } catch (error) {
      console.log("error occured ", error);
      throw new UnauthorizedException();
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    console.log("reached herer in fucnitn");
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}


@Injectable()
export class AuthorizeValidatedUser implements CanActivate {
  constructor(
    private jwtService: JwtService,
    @Inject('USER_REPOSITORY')
    private userRepository: Repository<User>,
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

      console.log("payload received ", payload);

      const user = await this.userRepository.findOneBy({id: payload.id});

      //checking if user exists in the database;
      if (!user) {
        throw new UnauthorizedException();
      }
      if(!user.isVerified){
        throw new HttpException("email is not verified yet.", HttpStatus.BAD_REQUEST);
      }
      if (payload.id) request['user'] = user;

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
