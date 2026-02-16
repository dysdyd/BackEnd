import { Controller, Post, Body, Get, UseGuards, Request, Ip, Headers } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, LoginUserDto } from './dto/auth.dto';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('join')
    async join(@Body() createUserDto: CreateUserDto) {
        await this.authService.join(createUserDto);
        return { success: true };
    }

    @Post('login')
    async login(
        @Body() loginUserDto: LoginUserDto,
        @Ip() ip: string,
        @Headers('user-agent') userAgent: string
    ) {
        const deviceEnv = `${ip}|${userAgent || 'unknown'}`;
        return this.authService.login(loginUserDto, deviceEnv);
    }

    @UseGuards(AuthGuard('jwt'))
    @Get('check')
    async check(@Request() req, @Ip() ip: string, @Headers('user-agent') userAgent: string) {
        // req.user is populated by JwtStrategy
        const userId = req.user.userId;
        // Extract token from header manually as we need to compare it against session
        const token = req.headers.authorization?.split(' ')[1];
        const deviceEnv = `${ip}|${userAgent || 'unknown'}`;

        return this.authService.check(userId, token, deviceEnv);
    }
}
