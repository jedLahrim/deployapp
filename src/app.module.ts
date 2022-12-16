import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { typeormOptions } from './config/config';
import { TypeOrmModule } from "@nestjs/typeorm";

@Module({
  imports: [TypeOrmModule.forRoot(typeormOptions)],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
