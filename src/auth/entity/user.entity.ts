import {
  BaseEntity,
  Entity,
  PrimaryGeneratedColumn,
  Column,
  Unique,
  OneToMany,
} from 'typeorm';
import { Exclude } from 'class-transformer';
import { MyCode } from "../../code/code.entity";

@Entity()
// @Unique(['username'])
export class User extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  username: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column()
  phone: string;

  @Column()
  address: string;

  @Column({ default: false })
  @Exclude()
  activated?: boolean;


  @OneToMany((_type) => MyCode, (code) => code.user, {
    eager: true,
    onDelete: 'CASCADE',
  })
  @Exclude()
  code: MyCode[];
  access: string;
  refresh: string;
  refresh_expire_at: Date;
  access_expire_at: Date;
}
