import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { CreateUserDto, LoginUserDto } from './dto/auth.dto';
import { User } from './entities/user.entity';
import { Session } from './entities/session.entity';
import { ValidationConstants } from '../utils/validation.constants';

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(User)
        private userRepository: Repository<User>,
        @InjectRepository(Session)
        private sessionRepository: Repository<Session>,
        private jwtService: JwtService
    ) { }

    async join(createUserDto: CreateUserDto): Promise<void> {
        const { email, password } = createUserDto;

        if (!ValidationConstants.EMAIL_REGEX.test(email)) {
            throw new BadRequestException('Invalid email format');
        }
        if (password.length < ValidationConstants.PASSWORD_MIN_LENGTH) {
            throw new BadRequestException('Password too short');
        }

        const existingUser = await this.userRepository.findOne({ where: { email } });
        if (existingUser) {
            throw new BadRequestException('Email already exists');
        }

        const salt = await bcrypt.genSalt();
        const passwordHash = await bcrypt.hash(password, salt);

        const newUser = this.userRepository.create({
            email,
            passwordHash,
        });

        await this.userRepository.save(newUser);
    }

    async login(loginUserDto: LoginUserDto, deviceEnv: string): Promise<{ accessToken: string }> {
        const user = await this.userRepository.findOne({ where: { email: loginUserDto.email } });

        if (!user || !(await bcrypt.compare(loginUserDto.password, user.passwordHash))) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const payload = { sub: user.id, email: user.email };
        const accessToken = await this.jwtService.signAsync(payload);

        let session = await this.sessionRepository.findOne({ where: { userId: user.id } });

        if (session) {
            session.token = accessToken;
            session.deviceEnv = deviceEnv;
            session.lastActive = new Date();
            await this.sessionRepository.save(session);
        } else {
            session = this.sessionRepository.create({
                userId: user.id,
                deviceEnv,
                token: accessToken,
            });
            await this.sessionRepository.save(session);
        }

        return { accessToken };
    }

    async check(userId: string, currentToken: string, deviceEnv: string): Promise<{ authenticated: true; user: { id: string, email: string } }> {
        const session = await this.sessionRepository.findOne({ where: { userId } });

        if (!session) {
            throw new UnauthorizedException('Session not found');
        }

        if (session.token !== currentToken) {
            throw new UnauthorizedException('Invalid session token');
        }

        if (session.deviceEnv !== deviceEnv) {
            await this.sessionRepository.remove(session);
            throw new UnauthorizedException('Session invalid: Device mismatch');
        }

        session.lastActive = new Date();
        await this.sessionRepository.save(session);

        const user = await this.userRepository.findOne({ where: { id: userId } });
        if (!user) throw new UnauthorizedException('User not found');

        return {
            authenticated: true,
            user: { id: user.id, email: user.email }
        };
    }
}
