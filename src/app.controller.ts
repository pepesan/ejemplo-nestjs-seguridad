import {
  Get,
  Post,
  UseGuards,
  Session,
  Request,
  Response,
  Controller,
} from '@nestjs/common';
import { JwtAuthGuard } from './auth/jwt-auth.guard';
import { LocalAuthGuard } from './auth/local-auth.guard';
import { AuthService } from './auth/auth.service';
import { Roles } from './auth/roles.decorator';
import { Role } from './auth/role.enum';
import { AuthenticatedGuard } from './auth/authenticated.guard';
import { LoginGuard } from './auth/login.guard';

@Controller()
export class AppController {
  constructor(private authService: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @UseGuards(LoginGuard)
  @Post('auth/login')
  async login(@Request() req, @Session() session: Record<string, any>) {
    const response = await this.authService.login(req.user);
    session.user = response.payload;
    return { access_token: response.access_token };
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req) {
    console.log(req.user);
    return req.user;
  }
  /*
    Manejo de sesiones
   */

  /*
    Objeto Session
   */
  @Get('sessions')
  findAllSessions(@Session() session: Record<string, any>) {
    session.visits = session.visits ? session.visits + 1 : 1;
    return session.visits;
  }
  /*
    Manejo de cookies
   */
  @Get('getcookies')
  getCookies(@Request() request) {
    console.log(request.cookies); // or "request.cookies['cookieKey']"
    // or console.log(request.signedCookies);
  }
  @Get('setcookies')
  SetCookie(@Response({ passthrough: true }) response) {
    response.cookie('key1', 'value', {
      maxAge: 1000 * 60 * 10,
      httpOnly: true,
    });
    /*
      cookie segura sólo con https
     */
    response.cookie('key2', 'value2', {
      maxAge: 1000 * 60 * 10,
      signed: true,
    });
  }
  /*
    Manejo de Roles
   */
  /*
    Acceso sólo con el rol de Admin
   */
  @Get('roles')
  @UseGuards(JwtAuthGuard)
  @UseGuards(AuthenticatedGuard)
  @Roles(Role.Admin)
  getRole(@Request() req, @Session() session: Record<string, any>) {
    return req.user.roles;
  }
  @Get('miguard')
  @UseGuards(AuthenticatedGuard)
  getGuard() {
    return 'logueado';
  }
}
