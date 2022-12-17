import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { Role } from './roles.enum';
import { AuthUserLoginDto } from '../dto/auth-user-login.dto';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requireRoles = this.reflector.getAllAndOverride<Role[]>('roles', [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requireRoles) {
      return true;
    }
    //const {user}=context.switchToHttp().getRequest();
    const user: AuthUserLoginDto = {
      username: 'joliX007',
      password: 'imTheBestInTown',
      roles: [Role.ADMIN],
    };

    return requireRoles.some((role) => user.roles.includes(role));
  }
}
