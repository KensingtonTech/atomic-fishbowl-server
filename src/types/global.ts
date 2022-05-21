/* eslint-disable @typescript-eslint/no-namespace */
export {};
import type { Socket as RawSocket } from 'engine.io';
import { JwtUser } from './jwt-user';
import { RollingCollectionManager } from '../rolling-collections';
import { Socket as NetSocket } from 'net';


declare global {
  namespace Express {
    // eslint-disable-next-line @typescript-eslint/no-empty-interface
    interface User extends JwtUser {}
  }

  type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;
}

declare module 'engine.io' {
  class Socket {
    jwtuser: JwtUser; // cannot be placed on socket.io:Socket class, as that object isn't shared in the way you might think, due to rooms, etc.  Just. don't. do. it.
  }
}

declare module 'socket.io' {
  class Socket {
    conn: RawSocket;
    collectionId?: string;
    collectionName?: string;
    rollingCollectionManager?: RollingCollectionManager;
    rollingId?: string;
    collectionType?: string;
  }
}

declare module 'child_process' {
  interface ChildProcess {
    workerSockets?: NetSocket[];
    // content: Content
  }
}