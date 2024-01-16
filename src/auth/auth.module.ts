import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { UserSchema } from '../users/schemas/user.schema';
import { MongooseModule } from '@nestjs/mongoose';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: "users", schema: UserSchema }]),
    UsersModule, 
    JwtModule.register({
    global: true,
    secret: process.env.secret,
    signOptions: { expiresIn: '1h' },
  }),],
  providers: [AuthService],
  controllers: [AuthController]
})
export class AuthModule {}
