import os
import sys
import socket
import asyncore
import asynchat
import json
import logging
from pprint import pprint, pformat

log = logging.getLogger(__name__)

class Communicator(asynchat.async_chat):

  def __init__(self, file, callback):
    asynchat.async_chat.__init__(self)
    self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.connect( file )
    self.set_terminator('\n')
    self.in_buffer = []
    self.out_buffer = ''
    self.callback = callback
    
  def collect_incoming_data(self, data):
    self.in_buffer.append(data)
    
  def found_terminator(self):
    msg = ''.join(self.in_buffer)
    self.in_buffer = []
    try:
      obj = json.loads(msg)
      self.callback(obj)
    except Exception as e:
      log.exception("Exception in found_terminator().  Exiting with code 1")
      sys.exit(1)
  
  def write_data(self, data):
    #print "communicator: write_data():", data
    '''
    Public facing interface method.  This is the function
    external code will use to send data to this dispatcher.
    '''
    self.out_buffer += data
    self.handle_write()
     
  def handle_write(self):
    #print "communicator: handle_write()"
    #Data must be placed in a buffer somewhere.
    #(In this case out_buffer)
    sent = self.send(self.out_buffer)
    self.out_buffer = self.out_buffer[sent:]
  
  """
  def readable(self):
    #Test for select() and friends
    return True
  """

  #There is no 'e' in 'writeable' here.
  def writable(self):
    #Test for select(). Must have data to write
    #otherwise select() will trigger
    if self.connected and len(self.out_buffer) > 0:
        return True
    return False

  def handle_close(self):
    #Flush the buffer
    #print "communicator: handle_close()"
    try:
      while self.writable():
        self.handle_write()
    except RuntimeError as e:
      log.error('Exception raised whilst handle_close() on communicator.  This probably means the server crashed.  Exiting with code 1')
      sys.exit(1)
    except Exception as e:
      log.exception('Unhandled exception raised whilst handle_close() on communicator.  Not sure what this means.  Exiting with code 1')
      sys.exit(1)
    self.close()


  
class HashServer(asyncore.dispatcher):

  def __init__(self, file, hasher):
    asyncore.dispatcher.__init__(self)
    self.hasher = hasher # instance of hasher class to pass to HashClientConnectionHandler
    self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.address = self.socket.getsockname()
    self.set_reuse_addr()
    self.bind( file )
    self.listen(5)

  def handle_accept(self):
    # Called when a client connects to our socket
    client_info = self.accept()
    #pprint(client_info[1])
    #log.debug('handle_accept() -> %s', client_info[1])
    #HashClientConnectionHandler(self.hasher, sock=client_info[0])
    HashClientConnectionHandler(self.hasher, sock=client_info[0])
    # We only want to deal with one client at a time,
    # so close as soon as we set up the handler.
    # Normally you would not do this and the server
    # would run forever or until it received instructions
    # to stop.
    #self.handle_close()
    return
  
  def handle_close(self):
    log.debug('handle_close()')
    self.close()
    return



class HashClientConnectionHandler(asynchat.async_chat):

  def __init__(self, hasher, sock):
    #log.debug("HashClientConnectionHandler: __init__()")
    asynchat.async_chat.__init__(self, sock=sock)
    self.hasher = hasher
    self.set_terminator('\n')
    self.in_buffer = []
    #self.out_buffer = ''

  def collect_incoming_data(self, data):
    #log.debug("HashClientConnectionHandler: collect_incoming_data()")
    self.in_buffer.append(data)
    
  def found_terminator(self):
    msg = ''.join(self.in_buffer)
    #log.debug('HashClientConnectionHandler: found_terminator(): msg:' + msg)
    self.in_buffer = []
    req = None
    try:
      req = json.loads(msg)
      #print(pformat(req))
    except Exception as e:
      log.exception("Exception parsing JSON in found_terminator()")
      return
    
    if 'getTypes' in req:
      res = self.hasher.getTypes(req['feedId'])
    if 'hash' in req:
      res = self.hasher.submit(req)

    #log.debug('HashClientConnectionHandler: found_terminator(): res:\n' + pformat(res))
    self.send(json.dumps(res) + '\n')