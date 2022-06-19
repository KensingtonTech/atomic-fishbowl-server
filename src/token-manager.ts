import schedule from 'node-schedule';
import log from './logging.js';
import { ConfigurationManager } from './configuration-manager.js';
import { Socket } from 'socket.io';
import { DatabaseManager } from './database.js';

export class TokenManager {

  private tokenBlacklist: Record<string, number> = {}; // number is a timestamp
  private afbConfig: ConfigurationManager;
  private dbMgr: DatabaseManager;
  private socketTokens: Record<string, Socket[]> = {}; // { [jti]: [socket1, socket2, socket3] } // keeps track of which sockets are associated with a given token
  private authenticatedSockets: Record<string, Socket> = {}; // { [socketId]: socket } // is used only for communication to authenticated sockets
  private scheduledJobs: Record<string, schedule.Job> = {}; // { [jti]: scheduleHandler }

  constructor(cfgMgr: ConfigurationManager, dbMgr: DatabaseManager) {
    this.afbConfig = cfgMgr;
    this.dbMgr = dbMgr;

    /*
    The token blacklist exists to prevent tokens that have been revoked, due to logout, from being reused during their validity period.
    We don't need all expired tokens to be added to it, as they'll be denied anyway by virtue of them being expired.
    We don't need to track the state of all tokens...
    We only need to track the state of tokens connected for which there is an open socket.io connection.
    When a token expires for an open socket, we want that socket be logged out and disconnected and its token blacklisted.
    We need those tokens to be added here when logging into a socket...
    and they need to be removed when disconnecting (and when they expire).
    */
    
  }



  addTokenToBlacklist(id: string, timestamp: number) {
    this.tokenBlacklist[id] = timestamp;
  }



  addSocketToken(socket: Socket) {
    this.authenticatedSockets[socket.id] = socket;
    const jti = socket.conn.jwtuser.jti;
    const expiryTime = socket.conn.jwtuser.exp;
    log.debug('TokenManager: addSocketToken(): adding socket token for jti:', jti);
    log.debug('TokenManager: addSocketToken(): expiryTime:', expiryTime);
    const expiryDate = new Date(expiryTime * 1000);
    if (!(jti in this.socketTokens)) {
      this.socketTokens[jti] = [];
    }
    this.socketTokens[jti].push(socket);
    if (!(jti in this.scheduledJobs)) {
      this.scheduledJobs[jti] = schedule.scheduleJob(expiryDate, () => this.onTokenExpired(jti) );
    }
  }



  removeSocketToken(socket: Socket, reason: string) {
    // deletes the expiry job for a socket and removes it from _socketTokens, _authenticatedSockets, and removes the socket's 'jwtuser'
    // called by onSocketIoDisconnect() and onTokenExpired()
    // it must expect that a socket may be either authenticated or unauthenticated
    // this can be determined by whether 'jwtuser' is in socket
    log.debug('TokenManager: removeSocketToken()');
    log.debug('TokenManager: removeSocketToken(): disconnect reason:', reason);
    if (reason === 'server namespace disconnect') {
      // we only want to run this routine if we didn't call disconnect from the server
      // without this guard, we could crash here (and who knows?  we still might)
      return;
    }
    if (!socket.conn.jwtuser) {
      log.debug('TokenManager: removeSocketToken(): this socket is not authenticated - returning');
      return;
    }
    const jti = socket.conn.jwtuser.jti;
    delete (socket.conn as any).jwtuser;

    const socketId = socket.id;
    delete this.authenticatedSockets[socketId]; // if this crashes, something is seriously wrong
    const sockets = this.socketTokens[jti];
    
    if (sockets?.length === 1) {
      const job = this.scheduledJobs[jti];
      job.cancel();
      delete this.scheduledJobs[jti];
      delete this.socketTokens[jti];
    }
    else if (sockets) {
      // we must find the appropriate socket to remove from _socketTokens
      sockets.forEachReverse(
        (thisSocket, i) => {
          if (thisSocket.id === socketId) {
            sockets.splice(i, 1);
          }
        }
      );
    }
  }



  removeSocketTokensByJwt(jti: string) {
    log.debug('TokenManager: removeSocketTokensByJwt()');
    // runs when a user logs out
    // called only from /api/logout
    // it kills the token's scheduled expiry job, and tells the clients to logout and downgrade their sockets
    // it removes the sockeet from _authenticatedSockets amd _socketTokens
    // it also removes socket.jwtuser from all sockets associated with the token

    if (jti in this.socketTokens) {
      const socketsOfToken = this.socketTokens[jti];
      socketsOfToken.forEach( (socket) => {
        const socketId = socket.id;
        log.debug('TokenManager: removeSocketTokensByJwt(): disconnecting socket', socket.id);
        socket.emit('logout', 'user logout');
        socket.emit('socketDowngrade');
        if (socketId in this.authenticatedSockets) {
          delete this.authenticatedSockets[socketId];
        }
        delete (socket as any).jwtuser; // unauthenticate the socket
      })
      delete this.socketTokens[jti];
    }
    else {
      log.debug(`TokenManager: removeSocketTokensByJwt(): token ${jti} was not found in socketTokens`);
    }

    if (jti in this.scheduledJobs) {
      log.debug('TokenManager: removeSocketTokensByJwt(): killing expiry job for token', jti);
      const job = this.scheduledJobs[jti];
      job.cancel();
      delete this.scheduledJobs[jti];
    }
    else {
      log.debug(`TokenManager: removeSocketTokensByJwt(): no scheduled jobs were found for token ${jti}`);
    }
    
  }



  async blacklistToken(id: string) {
    const timestamp = new Date().getTime();
    await this.dbMgr.insertRecord('blacklist', { id, timestamp }); // we want to die if there's an exception
    this.tokenBlacklist[id] = timestamp;
  }



  /**
   * Callback to run when a token has expired
   */
  onTokenExpired(jti: string) {
    log.debug('TokenManager: onTokenExpired(): jti:', jti);
    // tell the client we're disconnecting and then disconnect the socket
    this.socketTokens[jti].forEach( (socket) => {
      // there could be more than one socket using the same token (multiple tabs in same browser)
      socket.emit('logout', 'token expired'); // inform the client
      socket.emit('socketDowngrade');
      this.removeSocketToken(socket, 'token expired');
    });
   
  }



  async cleanBlackList() {
    // log.debug('TokenManager: cleanBlackList()');
    const currentTime = new Date().getTime();
    await Promise.all(
      Object.entries(this.tokenBlacklist)
        .map( async ([id, timestamp]) => {
          if ( currentTime >= timestamp + this.afbConfig.tokenExpirationSeconds * 1000) {
            await this.dbMgr.deleteRecord('blacklist', id); // we want to die if there's an exception
            delete this.tokenBlacklist[id];
          }
        }
      )
    )
  }



  authSocketsEmit(message: string, value: unknown) {
    Object.values(this.authenticatedSockets).forEach( (socket) => socket.emit(message, value));
  }



  isTokenBlacklisted(jti: string): boolean {
    return jti in this.tokenBlacklist;
  }
}
