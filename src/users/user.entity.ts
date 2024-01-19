// user.entity.ts
import { Entity, Column, PrimaryGeneratedColumn, OneToOne, JoinColumn } from 'typeorm';
import { Otp } from './otp.entity'; // Import the Otp entity

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ default: false })
  isVerified: boolean;

  @OneToOne(() => Otp, { cascade: true, eager: true }) // Define the relationship with Otp entity
  @JoinColumn()
  otp: Otp;
}
