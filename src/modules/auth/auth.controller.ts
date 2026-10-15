import { FastifyRequest, FastifyReply } from 'fastify';
import { AuthService } from './auth.service';
import { RegisterInput, LoginInput, RefreshInput } from './auth.schemas';

export class AuthController {
  constructor(private readonly authService: AuthService) {}

  async register(request: FastifyRequest<{ Body: RegisterInput }>, reply: FastifyReply) {
    const user = await this.authService.register(request.body, request.ip, request.headers['user-agent']);
    reply.status(201).send({ id: user.id, email: user.email });
  }

  async login(request: FastifyRequest<{ Body: LoginInput }>, reply: FastifyReply) {
    const { user, session, refreshTokenPlain } = await this.authService.login(
      request.body,
      request.ip,
      request.headers['user-agent']
    );

    const accessToken = await reply.jwtSign(
      { sub: user.id, role: user.role, sessionId: session.id, tokenUse: 'access' },
      { expiresIn: '15m' }
    );

    reply.send({
      accessToken,
      refreshToken: refreshTokenPlain,
      user: { id: user.id, email: user.email, role: user.role },
    });
  }

  async refresh(request: FastifyRequest<{ Body: RefreshInput }>, reply: FastifyReply) {
    const { user, session, refreshTokenPlain } = await this.authService.refresh(
      request.body.refreshToken,
      request.ip,
      request.headers['user-agent']
    );

    const accessToken = await reply.jwtSign(
      { sub: user.id, role: user.role, sessionId: session.id, tokenUse: 'access' },
      { expiresIn: '15m' } // Rotação completa
    );

    reply.send({
      accessToken,
      refreshToken: refreshTokenPlain,
    });
  }

  async logout(request: FastifyRequest, reply: FastifyReply) {
    const user = request.user as { sub: string; sessionId: string };
    if (!user || !user.sessionId) {
      return reply.status(400).send({ error: 'Session not found in token' });
    }
    
    await this.authService.logout(user.sessionId, user.sub, request.ip, request.headers['user-agent']);
    reply.send({ message: 'Logged out successfully' });
  }

  // Session Methods
  async getSessions(request: FastifyRequest, reply: FastifyReply) {
    const user = request.user as { sub: string };
    const sessions = await this.authService.listUserSessions(user.sub);
    reply.send({ sessions });
  }

  async revokeSession(request: FastifyRequest<{ Params: { id: string }}>, reply: FastifyReply) {
    const user = request.user as { sub: string };
    await this.authService.revokeSpecificSession(request.params.id, user.sub, request.ip, request.headers['user-agent']);
    reply.status(204).send();
  }

  async revokeAllSessions(request: FastifyRequest, reply: FastifyReply) {
    const user = request.user as { sub: string };
    await this.authService.revokeAllSessions(user.sub, request.ip, request.headers['user-agent']);
    reply.status(204).send();
  }
}
