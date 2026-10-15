import { z } from 'zod';

export const registerSchema = z.object({
  email: z.string().trim().toLowerCase().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters long').max(128, 'Password too long'),
});

export const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email('Invalid email address'),
  password: z.string().max(128).min(1, 'Password is required'),
});

export const refreshSchema = z.object({
  refreshToken: z.string().regex(/^[a-f0-9]{80}$/, 'Invalid refresh token'),
});

export const forgotPasswordSchema = z.object({
  email: z.string().trim().toLowerCase().email(),
});

export const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Token is required'),
  newPassword: z.string().max(128).min(8, 'Password must be at least 8 characters long'),
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type RefreshInput = z.infer<typeof refreshSchema>;
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;
