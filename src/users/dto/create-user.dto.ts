import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsEnum, IsNotEmpty, IsString, IsOptional, IsDate, MinLength, Matches } from 'class-validator';

export class CreateUserDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty({
    example: 'Parshant Khichi',
    required: true
 })
  name: string;

  // @IsString()
  // @IsOptional()
  // lname: string;

  @IsEmail()
  @ApiProperty({
    example: 'pk@gmail.com',
    required: true
  })
  email: string;

  // @IsDate()
  // dob: Date;
  @ApiProperty({
    example: 'abc@1234',
    required: true
  })
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]+$/, {
    message: 'Password must contain at least one letter and one number',
  })
  password: string;
  otp?: import("mongoose").Types.ObjectId | any;
  isVerified?: boolean
}
