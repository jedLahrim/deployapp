import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './jwt.strategy';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { User } from './entity/user.entity';
import { MailerModule } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';
import { MyCode } from '../code/code.entity';
import { APP_GUARD } from '@nestjs/core';
import { RolesGuard } from './roles/ roles.guard';

@Module({
  imports: [
    MailerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        return {
          transport: {
            host: 'smtp.sendgrid.net',
            auth: {
              user: 'apikey',
              pass: configService.get('SENDGRID_API_KEY'),
            },
          },
        };
      },
    }),
    PassportModule.register({ defaultStrategy: 'Jwt' }),
    JwtModule.register({
      secret: 'jolixIstheBest2032',
      signOptions: {
        expiresIn: '1d',
      },
    }),
    TypeOrmModule.forFeature([User, MyCode]),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy,
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
  ],
  exports: [JwtStrategy, PassportModule],
})
export class AuthModule {}
