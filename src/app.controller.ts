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

import { createCipheriv, createDecipheriv, createHash, randomBytes, scrypt } from "crypto";
import { promisify } from "util";

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
  getRole(@Request() req) {
    return req.user.roles;
  }
  @Get('miguard')
  @UseGuards(AuthenticatedGuard)
  getGuard() {
    return 'logueado';
  }
  /*
    Uso de cifrado
  */
  @Get('cifrado')
  async cifrado() {
    const iv = randomBytes(16);
    const password = 'Password used to generate key';

    // generando la clave de cifrado
    const key = (await promisify(scrypt)(password, 'salt', 32)) as Buffer;
    const cipher = createCipheriv('aes-256-ctr', key, iv);
    // Cifrado
    const textToEncrypt = 'Nest';
    const encryptedText = Buffer.concat([
      cipher.update(textToEncrypt),
      cipher.final(),
    ]);
    // Descrifrado
    const decipher = createDecipheriv('aes-256-ctr', key, iv);
    const decryptedText = Buffer.concat([
      decipher.update(encryptedText),
      decipher.final(),
    ]);

    return {
      textToCifer: textToEncrypt,
      encryptedText: encryptedText.toString(),
      decryptedText: decryptedText.toString(),
    };
  }
}
