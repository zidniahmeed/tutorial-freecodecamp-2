import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService{
    constructor(
        private prisma: PrismaService,
        private jwt:JwtService,
        private config:ConfigService
    ){}
    async signup(dto:AuthDto){

        const hash = await argon.hash(dto.password);

        try {
            const user = await this.prisma.user.create({
                data : {
                    email : dto.email,
                    hash,
                },
                select: {
                    id: true,
                    email: true,
                    createAt: true,
                } 
            });
            return user;
        } catch (error) {
            if(error instanceof PrismaClientKnownRequestError){
                if (error.code === 'P2002') {
                    throw new ForbiddenException(
                        'Credential Taken'
                    )
                }
            }
        }
    }
    async signin(dto: AuthDto){
        const user = await this.prisma.user.findUnique({
            where:{
                email: dto.email
            }
        })
        if(!user)
            throw new ForbiddenException(
                'Credential Incorrect'
            );
        
        const cekPassword = await argon.verify(user.hash, dto.password);

        if(!cekPassword)
            throw new ForbiddenException(
                'Credential Incorrect'
            );
        return this.signToken(user.id, user.email)
    }
    async signToken(userID:number, email:string):Promise<{acces_token: string}>{
        const payload ={
            sub:userID,
            email,
        };
        const secret = this.config.get('JWT_SECRET')
        const token = await this.jwt.signAsync(payload,{
            expiresIn : "15m",
            secret : secret
        })
        return {
            acces_token: token
        }
    }

}