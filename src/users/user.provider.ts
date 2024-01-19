import { DataSource } from 'typeorm';
import { User } from './user.entity';
import { Otp } from './otp.entity';

export const userProviders = [
  {
    provide: 'USER_REPOSITORY',
    useFactory: (dataSource: DataSource) => dataSource.getRepository(User),
    inject: ['DATA_SOURCE'],
  },
  {
    provide: 'OTP_REPOSITORY',
    useFactory: (dataSource: DataSource) => dataSource.getRepository(Otp),
    inject: ['DATA_SOURCE'],
  }
];