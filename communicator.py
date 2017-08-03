import os
import sys
import socket
import asyncore
import asynchat
import json
import logging

log = logging.getLogger(__name__)

class communicator(asynchat.async_chat):

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
    #self.in_buffer += data
    
  def found_terminator(self):
    #print "got terminator"
    msg = ''.join(self.in_buffer)
    #msg = self.in_buffer
    #print 'Received:', msg
    self.in_buffer = []
    #self.in_buffer = ''
    #print self.in_buffer
    try:
      obj = json.loads(msg)
    except Exception as e:
      log.exception("Exception in found_terminator().  Exiting with code 1")
      sys.exit(1)

    if 'workerConfig' in obj:
      self.callback(obj)
    else:
      log.error("No workerConfig found in received payload.  Exiting with code 1")  #this should in theory never happen
      sys.exit(1)
  
  """
  def close(self):
    #self.close()
    self.close_when_done()
  """
      
  """
  def handle_read(self):
    # Do something with data
    data = self.recv(4096)
    self.in_buffer += data
  """
  
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
    while self.writable():
        self.handle_write()
    self.close()
  
      
  #def handle_error(self, e, trace):
  #  print "communicator exception",e
    #print msg

  