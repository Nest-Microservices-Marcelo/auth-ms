import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';

import * as bcrypt from 'bcrypt';

import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super(); // esto es porque estamos heredando de PrismaClient y queremos acceder a sus métodos
  }

  // constructor(@Inject(NATS_SERVICE) private readonly client: ClientProxy) {}
  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected');
  }

  // # SIGN JWT
  async signJWT(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  // # VERIFY TOKEN
  async verifyToken(token: string) {
    try {
      // Verificar el token
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user: user,
        token: await this.signJWT(user), // Firmamos un nuevo token que durara otras dos horas
      };
    } catch (error) {
      console.log(error);
      throw new RpcException({
        status: 401,
        message: 'Invalid token',
      });
    }
  }

  // # REGISTER USER
  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, name, password } = registerUserDto;
    try {
      const user = await this.user.findUnique({
        where: {
          email: email,
        },
      });

      // Validar si el email ya existe
      if (user) {
        throw new RpcException({
          status: 400,
          message: 'Email already exists',
        });
      }

      // Si el email no existe, crear el usuario
      const newUser = await this.user.create({
        data: {
          email: email,
          password: bcrypt.hashSync(password, 10), // Encriptar la contraseña - HASH - BCRYPT
          name: name,
        },
      });

      const { password: __, ...rest } = newUser;

      return {
        user: rest,
        token: await this.signJWT(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  // # LOGIN USER
  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    try {
      const user = await this.user.findUnique({
        where: { email },
      });

      // Validar si el email ya existe
      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'User/Password not found',
        });
      }

      const isPasswordValid = bcrypt.compareSync(password, user.password);

      if (!isPasswordValid) {
        throw new RpcException({
          status: 400,
          message: 'User/Password not found',
        });
      }

      const { password: __, ...rest } = user;

      return {
        user: rest,
        token: await this.signJWT(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }
}
