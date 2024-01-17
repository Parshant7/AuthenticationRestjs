
import { Table, Column, Model, ForeignKey, BelongsTo } from 'sequelize-typescript';
import { OtpC } from './otp.entity';

@Table
export class Cat extends Model {
  @Column
  name: string;

  @Column({unique: true})
  email: string;

  @Column
  password: string;
  
  @Column({defaultValue:false})
  isVerified: boolean;
  
  @ForeignKey(() => OtpC)
  @Column
  otpId: number;

  @BelongsTo(() => OtpC)
  otp: OtpC;
}
