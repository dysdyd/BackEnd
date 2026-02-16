import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InMemoryStore } from '../stores/in-memory.store';

// TODO: Move to env vars
export const jwtConstants = {
    secret: 'DO_NOT_USE_THIS_IN_PRODUCTION_SECRET_KEY_12345',
    expiresIn: '1h',
};

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(private usersStore: InMemoryStore) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: jwtConstants.secret,
        });
    }

    async validate(payload: any) {
        // This method is called after the token is verified
        // We can add additional checks here if needed, or simply return the user
        const user = this.usersStore.findUserById(payload.sub);
        if (!user) {
            throw new UnauthorizedException();
        }
        return { userId: payload.sub, email: payload.email };
    }
}
