import { Injectable, ForbiddenException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import { Msg, Jwt } from './interfaces/auth.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  async signUp(dto: AuthDto): Promise<Msg> {
    const hashed = await bcrypt.hash(dto.password, 12);
    try {
      await this.prisma.user.create({
        data: {
          email: dto.email,
          hashedPassword: hashed,
        },
      });

      return {
        message: 'ok',
      };
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('this email is already taken');
        }
      }
      throw error;
    }
  }
  async login(dto: AuthDto): Promise<Jwt>{
    // userテーブルからemailを探す
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // userが存在しなかったら。
    if (!user) {
      throw new ForbiddenException('email or Password failed');
    }
    // userが存在していたらハッシュ化のパスワードと比較する
    const isValid = await bcrypt.compare(dto.password, user.hashedPassword);
    if (!isValid) {
      throw new ForbiddenException('email or Password failed');
    }
    // accessTokenを返す
    return this.generateJwt(user.id, user.email);
  }

  async generateJwt(userId: number, email: string) {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');
    const token = await this.jwt.signAsync(payload, {
      expiresIn: '5m',
      secret: secret,
    });

    return {
      accessToken: token,
    };
  }
}
