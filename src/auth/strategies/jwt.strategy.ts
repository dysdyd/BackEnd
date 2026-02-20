import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';

// TODO: Move to env vars
export const jwtConstants = {
    secret: 'DO_NOT_USE_THIS_IN_PRODUCTION_SECRET_KEY_12345',
    expiresIn: '1h',
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(
        @InjectRepository(User)
        private userRepository: Repository<User>,
    ) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: jwtConstants.secret,
        });
    }

    async validate(payload: any) {
        // This method is called after the token is verified
        // We can add additional checks here if needed, or simply return the user
        const user = await this.userRepository.findOne({ where: { id: payload.sub } });
        if (!user) {
            throw new UnauthorizedException();
        }
        return { userId: payload.sub, email: payload.email };
    }
}
