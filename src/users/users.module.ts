import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { MongooseModule } from '@nestjs/mongoose';
import { UserSchema } from './schemas/user.schema';
import { OtpSchema } from './schemas/otp.schema';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import { Cat } from './cat.entity';
import { OtpC } from './otp.entity';

@Module({
  imports: [
    ConfigModule.forRoot(),
    MongooseModule.forFeature([{ name: "users", schema: UserSchema }]),
    MongooseModule.forFeature([{ name: "otps", schema: OtpSchema }]),
    JwtModule.register({
      global: true,
      secret: process.env.secret,
      signOptions: { expiresIn: '1h' },
    }),
  ],
  controllers: [UsersController],
  providers: [UsersService,  {
      provide: 'CATS_REPOSITORY',
      useValue: Cat,
    },
    {
      provide: 'OTP_REPOSITORY',
      useValue: OtpC,
    }
  ],
  exports: [UsersService],

})
export class UsersModule {}
