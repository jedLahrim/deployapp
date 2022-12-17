import {
  Injectable,
  UnauthorizedException,
  Logger,
  ConflictException,
  InternalServerErrorException,
  HttpStatus,
  NotFoundException,
  HttpException,
  ForbiddenException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entity/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { JwtPayload } from './interface/jwt-payload.interface';
import { AppError } from '../commons/errors/app-error';
import {
  EMAIL_OR_PASSWORD_IS_INCORRECT,
  ERR_EMAIL_OR_USERNAME_ALREADY_EXIST,
  ERR_EXPIRED_CODE,
  ERR_SEND_MAIL,
} from '../commons/errors/errors-codes';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { AuthUserLoginDto } from './dto/auth-user-login.dto';
import { ConfigService } from '@nestjs/config';
import { MyCode } from '../code/code.entity';
import { Constant } from '../commons/constant';
import { AuthRegisterDto } from './dto/authRegister.dto';
import { AuthAdminLoginDto } from './dto/auth-admin-login.dto';
import { Role } from './roles/roles.enum';
import { MailerService } from "@nestjs-modules/mailer";

@Injectable()
export class AuthService {
  private logger = new Logger('AuthService');

  constructor(
    @InjectRepository(MyCode)
    private myCodeRepo: Repository<MyCode>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService,
    private mailerService: MailerService,
    private configService: ConfigService,
  ) {
  }

  // Register
  async signUp(authCredentialsDto: AuthCredentialsDto) {
    const { username, email, phone, address, password } = authCredentialsDto;

    // user.username = username;
    // user.email = email;
    // user.phone = phone;
    // user.address = address;
    const salt = await bcrypt.genSalt();
    const hashedPassword = await this.hashPassword(password, salt);

    const user = await this.userRepository.create({
      username,
      email,
      phone,
      address,
      password: hashedPassword,
    });
    try {
      const newUser = await this.userRepository.save(user);
      console.log(newUser);
      await this.sendMail(user.email, newUser);
    } catch (error) {
      if (error.code === '23505') {
        // duplicate username
        throw new ConflictException(
          new AppError('ERR', 'Username already exists'),
        );
      }
      if (error.code == 'ER_DUP_ENTRY') {
        throw new ConflictException(
          new AppError(ERR_EMAIL_OR_USERNAME_ALREADY_EXIST),
        );
      } else {
        console.log(error);
        throw new InternalServerErrorException();
      }
    }
  }

  private async hashPassword(password: string, salt: string): Promise<string> {
    return bcrypt.hash(password, salt);
  }

  async sendMail(email: string, user: User): Promise<any> {
    try {
      user = await this.userRepository.findOne({ where: { email } });
      console.log(user);
      const from = this.configService.get('SENDER_MAIL');
      const code = await this.generateCode(user);
      console.log(code.code);
      await this.mailerService.sendMail({
        to: user.email,
        from: from,
        subject: `Hi ${user.username} this is your activation code ${code.code}`,
        text:
          `Hello ${user.username} from eventApp ` +
          `this is your activation code ${code.code}`,
        //html: `Click <a href="${url}">here</a> to activate your account !`,
      });
    } catch (e) {
      console.log(e);
      throw new NotFoundException(
        new AppError(ERR_SEND_MAIL, 'email not found'),
      );
    }
  }

  async generateCode(user: User) {
    let code = Constant.randomCodeString(6);
    let expireAt = new Date(new Date().getTime() + 200000);
    const thisCode = this.myCodeRepo.create({
      code: code,
      expire_at: expireAt,
      user: user,
    });
    return this.myCodeRepo.save(thisCode);
  }

  // Login
  async signIn(authCredentialsDto: AuthUserLoginDto): Promise<User & any> {
    const { username, password } = authCredentialsDto;
    const user = await this.userRepository.findOne({ where: { username } });
    if (!user) {
      throw new InternalServerErrorException(
        new AppError('ERR', 'user not found'),
      );
    } else {
      if (user.activated === false) {
        throw new ConflictException(
          new AppError('ERR', 'you should activate your account'),
        );
      } else {

        if (user && (await bcrypt.compare(password, user.password))) {
          const payload = { username };
          const accessExpireIn = 86400000;
          const access = this.generateToken(payload, accessExpireIn);
          const access_expire_at = new Date(
            new Date().getTime() + accessExpireIn,
          );
          const refreshExpireIn = 172800000;
          const refresh = this.generateToken(payload, refreshExpireIn);
          const refresh_expire_at = new Date(
            new Date().getTime() + refreshExpireIn,
          );
          user.access = access;
          user.access_expire_at = access_expire_at;
          user.refresh = refresh;
          user.refresh_expire_at = refresh_expire_at;
          return user;
        } else {
          throw new UnauthorizedException(
            new AppError(EMAIL_OR_PASSWORD_IS_INCORRECT),
          );
        }
      }
    }
  }

  // Admin Login
  async adminLogin(authAdminLoginDto: AuthAdminLoginDto): Promise<User & any> {
    if (
      authAdminLoginDto.roles === Role.ADMIN &&
      authAdminLoginDto.username === 'joliX007' &&
      authAdminLoginDto.password === 'imTheBestInTown'
    ) {
      // function generatePermutation(a, size, n) {
      //   // if size becomes 1 then prints the obtained permutation
      //   if (size == 1) printArr(a, n);
      //   for (let i = 0; i < size; i + 1) {
      //     generatePermutation(a, size - 1, n);
      //     if (size % 2 == 1) {
      //       [a[0]] = [a[size - 1]];
      //       let swap = a[0];
      //       a[0] = a[size - 1];
      //       a[size - 1] = swap;
      //     }
      //       // If size is even, swap ith
      //     // and (size-1)th i.e last element
      //     else {
      //       let swap = a[i];
      //       a[i] = a[size - 1];
      //       a[size - 1] = swap;
      //     }
      //   }
      // }
      //
      // // Driver code
      // let a = [1, 2, 3];
      // generatePermutation(a, a.length, a.length);
      //
      // function printArr(a, n) {
      //   console.log(a);
      // }

      const { username, password } = authAdminLoginDto;
      const user = await this.userRepository.findOne({ where: { username } });
      if (!user) {
        throw new InternalServerErrorException(
          new AppError('ERR', 'user not found'),
        );
      } else {
        if (user.activated === false) {
          throw new ConflictException(
            new AppError('ERR', 'you should activate your account'),
          );
        } else {
          if (user && (await bcrypt.compare(password, user.password))) {
            const payload = { username };
            const accessExpireIn = 86400000;
            const access = this.generateToken(payload, accessExpireIn);
            const access_expire_at = new Date(
              new Date().getTime() + accessExpireIn,
            );
            const refreshExpireIn = 172800000;
            const refresh = this.generateToken(payload, refreshExpireIn);
            const refresh_expire_at = new Date(
              new Date().getTime() + refreshExpireIn,
            );
            user.access = access;
            user.access_expire_at = access_expire_at;
            user.refresh = refresh;
            user.refresh_expire_at = refresh_expire_at;
            return user;
          } else {
            throw new UnauthorizedException(
              new AppError(EMAIL_OR_PASSWORD_IS_INCORRECT),
            );
          }
        }
      }
    } else {
      throw new ForbiddenException(
        new AppError(
          'Forbidden resource',
          'you are not an Admin to have a login here',
        ),
      );
    }
  }

  async getUserWithTokens(user: User) {
    try {
      const payload1 = { user: user.username };
      const accessExpireIn = 864000000;
      const accessToken = this.generateToken(payload1, accessExpireIn);
      const access_expire_at = new Date(new Date().getTime() + accessExpireIn);

      const refreshExpireIn = 172800000;
      const refresh = this.generateToken(payload1, refreshExpireIn);
      const refresh_expire_at = new Date(new Date().getTime() + accessExpireIn);

      user.access = accessToken;
      user.access_expire_at = access_expire_at;
      user.refresh = refresh;
      user.refresh_expire_at = refresh_expire_at;
      return user;
    } catch (e) {
      throw new NotFoundException(
        new AppError('USER_NOT_FOUND', 'user not found'),
      );
    }
  }

  async getUserById(id: string): Promise<User> {
    const found = await this.userRepository.findOne({ where: { id } });
    if (!found) {
      throw new NotFoundException(
        new AppError('ID_NOT_FOUND', `user with id '${id}' not found`),
      );
    }
    return found;
  }

  async activate(code: any): Promise<User> {
    // EXPIRE_AT 20:15:20
    // new Date() 20:15:10
    const now = new Date();
    let found = await this.myCodeRepo.findOne({ where: { code: code } });
    if (!found) {
      throw new ConflictException('code is incorrect');
    }
    const user = await this.getUserById(found.user_id);
    if (user.code.length > 2) {
      throw new InternalServerErrorException(
        new AppError(`ERR`, 'account already activated'),
      );
    }
    if (found.expire_at < now) {
      throw new HttpException(
        new AppError(
          ERR_EXPIRED_CODE,
          'this code is expired try to send it again',
        ),
        HttpStatus.NOT_FOUND,
      );
    } else {
      user.activated = true;
      await this.userRepository.save(user);
      return this.getUserWithTokens(user);
    }
  }

  private generateToken(payload: any, expiresIn: number): string {
    return this.jwtService.sign(payload, {
      expiresIn: expiresIn,
      secret: 'jolixIstheBest2032',
    });
  }
}
