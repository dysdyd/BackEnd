import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy, jwtConstants } from './strategies/jwt.strategy';
import { InMemoryStore } from './stores/in-memory.store';

@Module({
    imports: [
        PassportModule,
        JwtModule.register({
            secret: jwtConstants.secret,
            signOptions: { expiresIn: jwtConstants.expiresIn as any },
        }),
    ],
    controllers: [AuthController],
    providers: [AuthService, JwtStrategy, InMemoryStore],
    exports: [AuthService],
})
export class AuthModule { }
