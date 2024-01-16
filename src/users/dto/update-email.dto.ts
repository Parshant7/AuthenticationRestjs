import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MinLength } from 'class-validator';

export class UpdateEmailDto {
  @IsEmail()
  @ApiProperty({
    example: 'pk@gmail.com',
    required: true
  })
  newEmail: string;
}

