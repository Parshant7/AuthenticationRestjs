import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsEnum, IsNotEmpty, IsString, IsOptional, IsDate, MinLength, Matches } from 'class-validator';
import { ObjectId } from 'mongoose';

export class ChangePasswordDto{

  @IsString()
  @MinLength(8, { message: 'Current Password must be at least 8 characters long' })
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]+$/, {
    message: 'Password must contain at least one letter and one number',
  })
  currentPassword: string;
  @IsString()
  @MinLength(8, { message: 'new Password must be at least 8 characters long' })
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]+$/, {
    message: 'Password must contain at least one letter and one number',
  })
  newPassword: string;
}
