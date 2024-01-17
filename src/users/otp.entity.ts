
import { Table, Column, Model, ForeignKey, BelongsTo, Length } from 'sequelize-typescript';

@Table
export class OtpC extends Model {

  @Column({unique: true})
  email: string;

  @Column
  pin: string;
  
  @Column({type:'TIMESTAMP', allowNull: false})
  createdAt: Date;

  @Column({type:'TIMESTAMP', allowNull: false})
  expiryDate: Date;

  @Column({defaultValue:false})
  isVerified: boolean;
  
}
