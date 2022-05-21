export interface SaServerTest {
  id?: string;
  host: string;
  port: number;
  ssl: boolean;
  user: string;
  password?: string;
}