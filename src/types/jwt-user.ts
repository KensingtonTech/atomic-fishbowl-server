export interface JwtUser {
  username: string;
  fullname: string;
  enabled: boolean;
  iat: number;
  exp: number;
  /**
   * User's _id
   */
  sub: string;
  jti: string;
}