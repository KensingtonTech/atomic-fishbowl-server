import os
import sys
import socket
#import asyncore
import asynchat
import json
import logging
import pprint

log = logging.getLogger(__name__)

class Communicator(asynchat.async_chat):

  def __init__(self, file, callback):
    asynchat.async_chat.__init__(self)
    self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
    #self.socket.settimeout(None)
    self.connect( file )
    self.set_terminator(b'\n')
    self.in_buffer = []
    self.out_buffer = b''
    self.callback = callback

  

  def collect_incoming_data(self, data):
    self.in_buffer.append(data)
    


  def found_terminator(self):
    msg = b''.join(self.in_buffer)
    self.in_buffer = []
    try:
      obj = json.loads(msg.decode('utf-8'))
    except Exception as e:
      log.exception("Exception in found_terminator().  Exiting with code 1")
      sys.exit(1)

    #pprint.pprint(obj)

    if 'heartbeat' in obj: # this is just to keep the socket open
      pass
      log.debug("got heartbeat")
    elif 'workerConfig' in obj:
      self.callback(obj)
    else:
      log.error("No identifiable attribute was found in received payload.  Exiting with code 1")  #this should in theory never happen
      sys.exit(1)
  


  def write_data(self, data):
    #print "communicator: write_data():", data
    '''
    Public facing interface method.  This is the function
    external code will use to send data to this dispatcher.
    '''
    self.out_buffer += data.encode('utf-8')
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





class FeederCommunicator(asynchat.async_chat):

  def __init__(self, file, callback):
    asynchat.async_chat.__init__(self)
    self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.socket.settimeout(None)
    self.connect( file )
    self.set_terminator(b'\n')
    self.in_buffer = []
    self.out_buffer = b''
    self.callback = callback



  def collect_incoming_data(self, data):
    self.in_buffer.append(data)



  def found_terminator(self):
    msg = b''.join(self.in_buffer)
    self.in_buffer = []
    try:
      obj = json.loads(msg.decode('utf-8'))
    except Exception as e:
      log.exception("Exception parsing JSON in found_terminator().  Exiting with code 1")
      sys.exit(1)

    self.callback(obj)


  
  def write_data(self, data):
    #print "FeederCommunicator: write_data():", data
    '''
    Public facing interface method.  This is the function
    external code will use to send data to this dispatcher.
    '''
    self.out_buffer += data.encode('utf-8')
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
    #log.debug("FeederCommunicator: handle_close()")
    #Flush the buffer
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

