import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { MailerModule } from '@nestjs-modules/mailer';

@Module({
  imports: [
    MailerModule.forRoot({
      transport: {
        host: 'smtp.ethereal.email',
        port: 587,
        auth: {
            user: 'laisha.erdman35@ethereal.email',
            pass: 'BYwjRExJEmUTSyd6YQ'
        }
      }
    }),
    ConfigModule.forRoot({ isGlobal: true, envFilePath: ['.env'] }),
    MongooseModule.forRoot(process.env.DATABASE_URL),
    UsersModule,
    AuthModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
