export interface User {
  _id: string;
  username: string;
  fullname?: string;
  email: string;
  enabled: boolean;
  password?: string;
}
