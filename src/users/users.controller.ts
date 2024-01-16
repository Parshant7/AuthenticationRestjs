import { Body, Controller, Get, Post, UseGuards, Request, Put, Patch } from '@nestjs/common';
import { Request as RequestExpress } from 'express';
import { UsersService } from './users.service';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from "./models/user.model";
import { LoginUserDto } from './dto/login-user.dto';
import { ApiBody, ApiResponse, ApiTags } from '@nestjs/swagger';
import { AuthorizeUser, AuthorizeValidatedUser } from '../auth/auth.guard';
import { ChangePasswordDto } from "./dto/change-password.dto";
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdateEmailDto } from './dto/update-email.dto';

@Controller('users')
export class UsersController {
    constructor(private readonly userService: UsersService){}

    @ApiTags('register User')
    @Post("/register")
    @ApiResponse({ status: 201, description: 'The record has been successfully created.'})
    @ApiResponse({ status: 401, description: 'Unauthorized.'})
    @ApiBody({
        type: CreateUserDto,
        description: 'Json structure for user object',
    })
    async register(@Body() user: CreateUserDto):Promise<User>{
        return this.userService.register(user);
    }

    @ApiTags('login User')
    @ApiBody({
        type: LoginUserDto,
        description: 'Json structure for user object',
    })
    @Post("/login")
    @ApiResponse({ status: 401, description: 'wrong email or password'})
    @ApiResponse({ status: 200, description: 'successfully login'})
    async login(@Body() user: LoginUserDto): Promise<User>{
        return this.userService.login(user);
    }

    @UseGuards(AuthorizeUser)
    @Post('/verifyEmail')
    async verifyEmail(@Request() req: RequestExpress) {
      return this.userService.verifyEmail(req);
    }

    @UseGuards(AuthorizeValidatedUser)
    @Put('/refreshOtp')
    async refreshOtp(@Request() req: RequestExpress) {
      return this.userService.refreshOtp(req);
    }

    @UseGuards(AuthorizeValidatedUser)
    @Patch('/changePassword')
    async changePassword(@Request() req: RequestExpress, @Body() body: ChangePasswordDto) {
      return this.userService.changePassword(req, body);
    }

    @UseGuards(AuthorizeValidatedUser)
    @Patch('/forgotPassword')
    async forgotPassword(@Request() req: RequestExpress, @Body() body: ForgotPasswordDto) {
      return this.userService.forgotPassword(req, body);
    }

    @UseGuards(AuthorizeValidatedUser)
    @Patch('/resetPassword')
    async resetPassword(@Request() req: RequestExpress, @Body() body: ResetPasswordDto) {
        return this.userService.resetPassword(req, body);
    }

    @UseGuards(AuthorizeValidatedUser)
    @Patch('/emailUpdateRequest')
    async changeEmail(@Request() req: RequestExpress, @Body() body: UpdateEmailDto) {
        return this.userService.emailUpdateRequest(req, body);
    }

    @UseGuards(AuthorizeValidatedUser)
    @Patch('/updateEmail')
    async changeEmail(@Request() req: RequestExpress, @Body() body: UpdateEmailDto) {
        return this.userService.emailUpdateRequest(req, body);
    }
}
