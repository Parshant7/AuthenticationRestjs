import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MinLength } from 'class-validator';

export class LoginUserDto {
  @IsEmail()
  @ApiProperty({
    example: 'pk@gmail.com',
    required: true
  })
  email: string;

  @IsString()
  @ApiProperty({
    example: 'abcd@1234',
    required: true
  })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  password: string;
}
