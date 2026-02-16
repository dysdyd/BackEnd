import { Injectable, UnauthorizedException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { CreateUserDto, LoginUserDto } from './dto/auth.dto';
import { InMemoryStore, User, Session } from './stores/in-memory.store';
import { ValidationConstants } from '../utils/validation.constants';

@Injectable()
export class AuthService {
    constructor(
        private usersStore: InMemoryStore,
        private jwtService: JwtService
    ) { }

    async join(createUserDto: CreateUserDto): Promise<void> {
        const { email, password } = createUserDto;

        // TODO: move validation to pipe later, doing manual check for now based on plan
        if (!ValidationConstants.EMAIL_REGEX.test(email)) {
            throw new BadRequestException('Invalid email format');
        }
        if (password.length < ValidationConstants.PASSWORD_MIN_LENGTH) {
            throw new BadRequestException('Password too short');
        }

        if (this.usersStore.findUserByEmail(email)) {
            throw new BadRequestException('Email already exists');
        }

        const salt = await bcrypt.genSalt();
        const passwordHash = await bcrypt.hash(password, salt);

        const newUser: User = {
            id: uuidv4(),
            email,
            passwordHash,
            createdAt: new Date(),
        };

        this.usersStore.createUser(newUser);
    }

    async login(loginUserDto: LoginUserDto, deviceEnv: string): Promise<{ accessToken: string }> {
        const user = this.usersStore.findUserByEmail(loginUserDto.email);

        if (!user || !(await bcrypt.compare(loginUserDto.password, user.passwordHash))) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const payload = { sub: user.id, email: user.email };
        const accessToken = await this.jwtService.signAsync(payload);

        // Create or Update Session
        const session: Session = {
            userId: user.id,
            deviceEnv,
            token: accessToken,
            lastActive: new Date(),
        };

        // This overwrites any existing session for this user
        this.usersStore.createSession(user.id, session);

        return { accessToken };
    }

    async check(userId: string, currentToken: string, deviceEnv: string): Promise<{ authenticated: true; user: { id: string, email: string } }> {
        const session = this.usersStore.findSession(userId);

        if (!session) {
            throw new UnauthorizedException('Session not found');
        }

        // specific URL check logic: verify token matches stored session token
        if (session.token !== currentToken) {
            throw new UnauthorizedException('Invalid session token');
        }

        // specific URL check logic: verify device/IP matches stored session
        // In a real scenario, we might allow some leeway or specific logic
        if (session.deviceEnv !== deviceEnv) {
            // Invalidate session?
            this.usersStore.deleteSession(userId);
            throw new UnauthorizedException('Session invalid: Device mismatch');
        }

        // Refresh last active?
        session.lastActive = new Date();

        const user = this.usersStore.findUserById(userId);
        if (!user) throw new UnauthorizedException('User not found');

        return {
            authenticated: true,
            user: { id: user.id, email: user.email }
        };
    }
}
