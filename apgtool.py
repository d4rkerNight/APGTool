#!/usr/bin/env python2
#
# CC0 1.0 Universal
# <2014>  <t3sl4/tesla23>
#
# --------------------------------------------------------------------
# Generate random password
# && encrypt it into a file
# || decrypt an existing password
#
# Project will be maintained @
#
# https://github.com/t3sl4/apg-tool
#
#


import os
import sys
import random
import base64
import string
import signal
import getpass
from Crypto.Cipher import AES

R = '\033[91m'
W = '\033[97m'
G = '\033[92m'
N = '\033[0m'

fpath = sys.path[0]
splatform = sys.platform

print '' + W
print '####################################'
print '#                                  #'
print '# APG tool                         #'
print '#                                  #'
print '# Advanced Password Generator Tool #'
print '#                                  #'
print '# By tesla                         #'
print '#                                  #'
print '####################################'

def signal_handler(signal, frame):
  print '' + W
  print 'Quitting..'
  print '' + N
  sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def start_options():
  print '' + W
  print '[1] Generate Password'
  print '[2] Decrypt Password'
  print '[3] Quit'
  print '' + N

def start_char():
  print '' + W
  print '[d] Decimal'
  print '[l] Lowercase'
  print '[u] Uppercase'
  print '[p] Punctuation'
  print '[r] Random'
  print ''
  schar = raw_input('Password start with [r]: ' + N)
  if schar is '':
    schar = 'r'
  return schar

def makepasswd():
  while True:
    block_size = raw_input(W + 'Choose block size (16,24,32) [32]: ' + N)
    if block_size == '':
      block_size = 32
      break
    elif block_size == '16':
      block_size = 16
      break
    elif block_size == '24':
      block_size = 24
      break
    elif block_size == '32':
      block_size = 32
      break
    else:
      print R + 'Wrong choice!' + N
  
  while True:
    decimal = raw_input(W + 'Number of decimals [5]: ' + N)
    if decimal is '':
      decimal = 5
      break
    elif decimal.isdigit():
      break
    else:
      print R + 'Input a decimal!' + N
      
  while True:
    lowercase = raw_input(W + 'Number of lowercases [5]: ' + N)
    if lowercase is '':
      lowercase = 5
      break
    elif lowercase.isdigit():
      break
    else:
      print R + 'Input a decimal!' + N

  while True:
    uppercase = raw_input(W + 'Number of uppercases [5]: ' + N)
    if uppercase is '':
      uppercase = 5
      break
    elif uppercase.isdigit():
      break
    else:
      print R + 'Input a decimal!' + N

  while True:
    punct = raw_input(W + 'Number of punctuations [5]: ' + N)
    if punct is '':
      punct = 5
      break
    elif punct.isdigit():
      break
    else:
      print R + 'Input a decimal!' + N
      
  username = raw_input(W + 'Username [<empty>]: ' + N)
  if username is '':
    username = '<empty>'
  file_name = raw_input(W + 'File name [apg-pass]: ' + N)
  if file_name is '':
    file_name = 'apg-pass'
  
  while True:
    file_path = raw_input(W + 'File path [' + fpath + ']: ' + N)
    if file_path is '':
      if splatform[:3] is 'win':
        file_path = fpath + '\\'
      else:
        file_path = fpath + '/'
    if os.path.exists(file_path):
      break
    else:
      print R + 'Path does not exist!' + N
  passwd = ''
  if int(decimal) > 0:
    i = 0
    while i < int(decimal):
      passwd += ''.join(random.choice(string.digits))
      i += 1
  if int(lowercase) > 0:
    i = 0
    while i < int(lowercase):
      passwd += ''.join(random.choice(string.ascii_lowercase))
      i += 1
  if int(uppercase) > 0:
    i = 0
    while i < int(uppercase):
      passwd += ''.join(random.choice(string.ascii_uppercase))
      i += 1
  if int(punct) > 0:
    i = 0
    while i < int(punct):
      passwd += ''.join(random.choice(string.punctuation))
      i += 1

  shuffle = list(passwd)
  random.shuffle(shuffle)
  passwd = ''.join(shuffle)
  
  while True:
    schar = start_char()
    if schar is 'r':
      passwd = ''.join(shuffle)
      break
    elif schar is 'd':
      cnt = 0
      passwd = list(passwd)
      for d in passwd:
        if d in string.digits:
          position = cnt
          break
        cnt += 1
      passwd.insert(0, passwd.pop(cnt))
      passwd = ''.join(passwd)
      break
    elif schar is 'l':
      cnt = 0
      passwd = list(passwd)
      for l in passwd:
        if l in string.ascii_lowercase:
          position = cnt
          break
        cnt += 1
      passwd.insert(0, passwd.pop(cnt))
      passwd = ''.join(passwd)
      break
    elif schar is 'u':
      cnt = 0
      passwd = list(passwd)
      for u in passwd:
        if u in string.ascii_uppercase:
          position = cnt
          break
        cnt += 1
      passwd.insert(0, passwd.pop(cnt))
      passwd = ''.join(passwd)
      break
    elif schar is 'p':
      cnt = 0
      passwd = list(passwd)
      for p in passwd:
        if p in string.punctuation:
          position = cnt
          break
        cnt += 1
      passwd.insert(0, passwd.pop(cnt))
      passwd = ''.join(passwd)
      break
    else:
      print '' + R
      print 'Wrong choice!' + N

  print W + 'Password: ' + G + passwd + N
  print ''

  while True:
    padding1 = getpass.getpass(W + 'Padding [one char]: ' + N)
    if len(padding1) is 1:
      padding2 = getpass.getpass(W + 'Confirm Padding: ' + N)
      if padding1 == padding2:
        break
      else:
        print '' + R
        print 'Paddings do not match!'
        print '' + N
    else:
      print '' + R
      print 'Padding length is %d, it must be 1 char!' % (len(padding1),)
      print '' + N

  while True:
    key1 = getpass.getpass(W + 'Cipher Key [' + str(block_size) + ' char]: ' + N)
    if len(key1) is block_size:
      key2 = getpass.getpass(W + 'Confirm Cipher Key: ' + N)
      if key1 == key2:
        break
      else:
        print '' + R
        print 'Ciphers do not match!'
        print '' + N
    else:
      print '' + R
      print 'Cipher length is %d, it must be %d!' % (len(key1), block_size)
      print '' + N

  pad = lambda s: s + (block_size - len(s) % block_size) * padding1
  encAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
  cipher = AES.new(key1)
  encoded = encAES(cipher, passwd)
  ofile = open(file_path + file_name, 'a')
  ofile.write(username + '::' + encoded + '\n')
  ofile.close()
  print '' + W
  print 'Done!'
  print '' + N

def decryptpasswd():
  pass_enc = raw_input(W + 'Password to decode: ' + N)
  padding = getpass.getpass(W + 'Padding: ')
  decAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(padding)
  key = getpass.getpass('Cipher Key: ')
  cipher = AES.new(key)
  decoded = decAES(cipher, pass_enc)
  print 'Decrypted Passwd: ' + G + decoded + N

while True:
  start_options()
  case = raw_input(W + 'Please Select: ' + N)
  if case is '1':
    print ''
    makepasswd()
  elif case is '2':
    print ''
    decryptpasswd()
  elif case is '3':
    print '' + W
    print 'Bye!'
    print '' + N
    exit(0)
  else:
    print R + 'Wrong Choice!' + N
