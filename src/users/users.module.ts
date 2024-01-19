import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
// import { MongooseModule } from '@nestjs/mongoose';
// import { UserSchema } from './schemas/user.schema';
// import { OtpSchema } from './schemas/otp.schema';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from "../database/database.module";
import { userProviders } from './user.provider';

@Module({
  imports: [
    ConfigModule.forRoot(),
    JwtModule.register({
      global: true,
      secret: process.env.secret,
      signOptions: { expiresIn: '1h' },
    }),
    DatabaseModule
  ],
  controllers: [UsersController],
  providers: [UsersService, ...userProviders],
  exports: [UsersService],

})
export class UsersModule {}
