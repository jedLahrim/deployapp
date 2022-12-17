import { IsEnum, IsOptional, IsString, MaxLength, MinLength } from "class-validator";
import { Role } from "../roles/roles.enum";

export class AuthAdminLoginDto {
  @IsString()
  @MinLength(4)
  @MaxLength(20)
  username: string;

  @IsString()
  @MinLength(8)
  @MaxLength(20)
  password: string;

  @IsEnum(Role, {
    message: 'this role must be a valid role',
  })
  @IsOptional()
  roles?: string;
}
