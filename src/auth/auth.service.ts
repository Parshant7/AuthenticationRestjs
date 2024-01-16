import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(private userService: UsersService, private jwtService: JwtService){}

    async signIn(email:string, pass: string): Promise<any> {
        console.log("email", email, "password", pass);

        const user = await this.userService.findOne(email);
        console.log("this is user ", user);

        if( !user){
            throw new UnauthorizedException();
        }

        const isMatch = await bcrypt.compare(
            pass,
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

}
