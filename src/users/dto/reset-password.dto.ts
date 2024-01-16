import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, Matches, MaxLength, MinLength } from 'class-validator';

export class ResetPasswordDto {
   
    @ApiProperty({
        example: '111111',
        required: true
    })
    @IsString()
    @MinLength(6)
    @MaxLength(6)
    otp: string;

    @ApiProperty({
      example: 'abc@1234',
      required: true
    })
    @IsString()
    @MinLength(8, { message: 'Password must be at least 8 characters long' })
    @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]+$/, {
      message: 'Password must contain at least one letter and one number',
    })
    newPassword: string;

    @ApiProperty({
      example: 'abc@1234',
      required: true
    })
    @IsString()
    @MinLength(8, { message: 'Password must be at least 8 characters long' })
    @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]+$/, {
      message: 'Password must contain at least one letter and one number',
    })
    confirmPassword: string;
}
