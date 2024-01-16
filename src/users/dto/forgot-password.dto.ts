import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MinLength } from 'class-validator';

export class ForgotPasswordDto {
    @ApiProperty({
        example: 'pk@gmail.com',
        required: true
    })
    @IsString()
    email: string;
}
