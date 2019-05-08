class TokenManager {

  constructor(cfgMgr, dbMgr) {
    
    this.cfgMgr = cfgMgr;
    this.dbMgr = dbMgr;
    this._tokenBlacklist = {};
    this._socketTokens = {}; // { [jti]: [socket1, socket2, socket3] } // keeps track of which sockets are associated with a given token
    this._scheduledJobs = {}; // { [jti]: scheduleHandler }
    this._authenticatedSockets = {}; // { [socketId]: socket } // is used only for communication to authenticated sockets

    /*
    The token blacklist exists to prevent tokens that have been revoked, due to logout, from being reused during their validity period.
    We don't need all expired tokens to be added to it, as they'll be denied anyway by virtue of them being expired.
    We don't need to track the state of all tokens...
    We only need to track the state of tokens connected for which there is an open socket.io connection.
    When a token expires for an open socket, we want that socket be logged out and disconnected and its token blacklisted.
    We need those tokens to be added here when logging into a socket...
    and they need to be removed when disconnecting (and when they expire).
    */
    
  }



  addSocketToken(socket) {
    this._authenticatedSockets[socket.id] = socket;
    let jti = socket.conn.jwtuser.jti;
    let expiryTime = socket.conn.jwtuser.exp;
    winston.debug('TokenManager: addSocketToken(): adding socket token for jti:', jti);
    winston.debug('TokenManager: addSocketToken(): expiryTime:', expiryTime);
    let expiryDate = new Date(expiryTime * 1000);
    if (!(jti in this._socketTokens)) {
      this._socketTokens[jti] = [];
    }
    this._socketTokens[jti].push(socket);
    if (!(jti in this._scheduledJobs)) {
      this._scheduledJobs[jti] = schedule.scheduleJob(expiryDate, () => this.onTokenExpired(jti) );
    }
  }



  removeSocketToken(socket, reason) {
    // deletes the expiry job for a socket and removes it from _socketTokens, _authenticatedSockets, and removes the socket's 'jwtuser'
    // called by onSocketIoDisconnect() and onTokenExpired()
    // it must expect that a socket may be either authenticated or unauthenticated
    // this can be determined by whether 'jwtuser' is in socket.conn
    winston.debug('TokenManager: removeSocketToken()');
    winston.debug('TokenManager: removeSocketToken(): disconnect reason:', reason);
    if (reason === 'server namespace disconnect') {
      // we only want to run this routine if we didn't call disconnect from the server
      // without this guard, we could crash here (and who knows?  we still might)
      return;
    }
    if (!('jwtuser' in socket.conn)) {
      winston.debug('TokenManager: removeSocketToken(): this socket is not authenticated - returning');
      return;
    }
    let jti = socket.conn.jwtuser.jti;
    delete socket.conn['jwtuser'];

    let socketId = socket.id;
    delete this._authenticatedSockets[socketId]; // if this crashes, something is seriously wrong
    
    if (this._socketTokens[jti].length === 1) {
      let job = this._scheduledJobs[jti];
      job.cancel();
      delete this._scheduledJobs[jti];
      delete this._socketTokens[jti];
    }
    else {
      // we must find the appropriate socket to remove from _socketTokens
      let sockets = this._socketTokens[jti];
      let socketIdToFind = socket.id;
      for (let i = 0; i < sockets.length; i++) {
        let thisSocket = sockets[i];
        let socketId = thisSocket.id;
        if (socketId === socketIdToFind) {
          // this is the socket we want to purge.  Let's do it
          this._socketTokens[jti].splice(i, 1);
          break;
        }
      }
    }
  }



  removeSocketTokensByJwt(jti) {
    winston.debug('TokenManager: removeSocketTokensByJwt()');
    // runs when a user logs out
    // called only from /api/logout
    // it kills the token's scheduled expiry job, and tells the clients to logout and downgrade their sockets
    // it removes the sockeet from _authenticatedSockets amd _socketTokens
    // it also removes socket.conn.jwtuser from all sockets associated with the token

    if (jti in this._socketTokens) {
      let socketsOfToken = this._socketTokens[jti];
      socketsOfToken.forEach( (socket) => {
        let socketId = socket.id;
        winston.debug('TokenManager: removeSocketTokensByJwt(): disconnecting socket', socket.id);
        socket.emit('logout', 'user logout');
        socket.emit('socketDowngrade');
        if (socketId in this._authenticatedSockets) {
          delete this._authenticatedSockets[socketId];
        }
        delete socket.conn['jwtuser']; // unauthenticate the socket
      })
      delete this._socketTokens[jti];
    }
    else {
      winston.debug(`TokenManager: removeSocketTokensByJwt(): token ${jti} was not found in socketTokens`);
    }

    if (jti in this._scheduledJobs) {
      winston.debug('TokenManager: removeSocketTokensByJwt(): killing expiry job for token', jti);
      let job = this._scheduledJobs[jti];
      job.cancel();
      delete this._scheduledJobs[jti];
    }
    else {
      winston.debug(`TokenManager: removeSocketTokensByJwt(): no scheduled jobs were found for token ${jti}`);
    }
    
  }



  async blacklistToken(id) {
    let timestamp = new Date().getTime();
    await this.dbMgr.insertRecord('blacklist', { id: id, timestamp: timestamp }); // we want to die if there's an exception
    this._tokenBlacklist[id] = timestamp;
  }



  get tokenBlacklist() {
    return this._tokenBlacklist;
  }



  onTokenExpired(jti) {
    // callback to run when a token has expired
    winston.debug('TokenManager: onTokenExpired(): jti:', jti);
    // delete this._scheduledJobs[jti]; // handled in removeSocketToken()
    // tell the client we're disconnecting and then disconnect the socket
    this._socketTokens[jti].forEach( (socket) => {
      // there could be more than one socket using the same token (multiple tabs in same browser)
      socket.emit('logout', 'token expired'); // inform the client
      // socket.disconnect();
      socket.emit('socketDowngrade');
      this.removeSocketToken(socket, 'token expired');
    });
    // delete this._socketTokens[jti]; // handled in removeSocketToken()
    
  }



  async cleanBlackList() {
    // winston.debug('TokenManager: cleanBlackList()');
    let currentTime = new Date().getTime();
    for (let id in this._tokenBlacklist) {
      if (this._tokenBlacklist.hasOwnProperty(id)) {
        let timestamp = this._tokenBlacklist[id];
        if ( currentTime >= timestamp + this._tokenExpirationSeconds * 1000) {
          // winston.debug('TokenManager: cleanBlackList(): cleaning token with id', id);
          await this.dbMgr.deleteRecord('blacklist', id); // we want to die if there's an exception
          delete this._tokenBlacklist[id];
        }
      }
    }
  }



  authSocketsEmit(message, value = null) {
    Object.values(this._authenticatedSockets).forEach( (socket) => {
      if (value) {
        socket.emit(message, value);
      }
      else {
        socket.emit(message);
      }
    });
  }


}

module.exports = TokenManager;