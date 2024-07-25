import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  constructor(private jwtService: JwtService) {
    super();
  }

  private readonly logger = new Logger('AuthService');
  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected');
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { name, email, password } = registerUserDto;
    try {
      const existingUser = await this.user.findUnique({
        where: {
          email: email,
        },
      });
      if (existingUser) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'User already exists',
        });
      }

      const newUser = await this.user.create({
        data: {
          email: email,
          password: bcrypt.hashSync(password, 10),
          name: name,
        },
      });

      const returnedUser = {
        id: existingUser.id,
        name: existingUser.name,
        email: existingUser.email,
      };
      const token = await this.jwtService.signAsync(returnedUser);

      return {
        user: returnedUser,
        token: token,
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    try {
      const existingUser = await this.user.findUnique({
        where: {
          email: email,
        },
      });
      if (!existingUser) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: "User doesn't exist",
        });
      }

      const isPasswordValid = bcrypt.compareSync(
        password,
        existingUser.password,
      );

      if (!isPasswordValid) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'Invalid password',
        });
      }

      const returnedUser = {
        id: existingUser.id,
        name: existingUser.name,
        email: existingUser.email,
      };
      const token = await this.jwtService.signAsync(returnedUser);

      return {
        user: returnedUser,
        token: token,
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: error.message,
      });
    }
  }

  async verifyUser(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.secret,
      });

      return {
        user: user,
        token: await this.jwtService.sign({
          id: user.id,
          name: user.name,
          email: user.email,
        }),
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: error.message,
      });
    }
  }
}
