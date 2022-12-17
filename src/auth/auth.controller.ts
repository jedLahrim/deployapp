import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  UseGuards,
  ValidationPipe,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { AuthUserLoginDto } from './dto/auth-user-login.dto';
import { User } from './entity/user.entity';
import { GetUser } from './decorator/get-user.decorator';
import { AuthGuard } from '@nestjs/passport';
import { Roles } from './roles/roles.decorator';
import { Role } from './roles/roles.enum';
import { AuthRegisterDto } from './dto/authRegister.dto';
import { RolesGuard } from './roles/ roles.guard';
import { AuthAdminLoginDto } from './dto/auth-admin-login.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/signup')
  // @Roles(Role.ADMIN)
  signUp(
    @Body(ValidationPipe) authCredentialsDto: AuthCredentialsDto,
  ): Promise<void> {
    return this.authService.signUp(authCredentialsDto);
  }

  @Post('/signin')
  // @Roles(Role.ADMIN)
  signIn(
    @Body(ValidationPipe) authUserLoginDto: AuthUserLoginDto,
  ): Promise<{ token: string; user: string; id: number }> {
    return this.authService.signIn(authUserLoginDto);
  }

  @Post('/login')
  @Roles(Role.ADMIN)
  adminLogin(
    @Body(ValidationPipe) authAdminLoginDto: AuthAdminLoginDto,
  ): Promise<{ token: string; user: string; id: number }> {
    return this.authService.adminLogin(authAdminLoginDto);
  }

  @Post('verify_code')
  // @UseGuards(AuthGuard())
  async activate(@Body('code') code: any): Promise<User & any> {
    return this.authService.activate(code);
  }

  @Post('send-email')
  // @UseGuards(AuthGuard())
  async sendEmail(
    @Query('email') email: string,
    @GetUser() user: User,
  ): Promise<any> {
    return this.authService.sendMail(email, user);
  }
  @Get()
  @UseGuards(AuthGuard('jwt'))
  getUser(@GetUser() user: User) {
    console.log(user);
    return user;
  }
}
