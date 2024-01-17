import { Sequelize } from 'sequelize-typescript';
import { Cat } from '../users/cat.entity';
import { OtpC } from '../users/otp.entity';

export const databaseProviders = [
  {
    provide: 'SEQUELIZE',
    useFactory: async () => {
      const sequelize = new Sequelize({
        dialect: 'mysql',
        host: 'localhost',
        port: 3306,
        username: 'root',
        password: 'password',
        database: 'firstDB',
      });
      sequelize.addModels([Cat, OtpC]);
      await sequelize.sync();
      return sequelize;
    },
  },
];