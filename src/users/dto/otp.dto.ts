import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MaxLength, MinLength } from 'class-validator';

export class OtpDto {
  @IsString()
  @ApiProperty({
    example: '123456',
    required: true
  })
  @MinLength(6, { message: 'otp must be at 6 characters long' })
  @MaxLength(6, { message: 'otp must be at 6 characters long' })
  otp: string;
}
