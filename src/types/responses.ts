import { User } from './user';

export interface LoginResponse {
  success: true;
  user: User;
  sessionId: string;
}
