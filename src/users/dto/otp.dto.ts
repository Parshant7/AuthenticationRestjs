import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MaxLength, MinLength } from 'class-validator';

export class LoginUserDto {
  @IsString()
  @ApiProperty({
    example: 'abcd@1234',
    required: true
  })
  @MinLength(8, { message: 'otp must be at 8 characters long' })
  @MaxLength(8, { message: 'otp must be at 8 characters long' })
  Otp: string;
}
