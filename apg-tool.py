#!/usr/bin/env python2
#
# Copyright (C) <2014>  <t3sl4>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
#
# --------------------------------------------------------------------
# Generate random password
# && encrypt it into a file
# || decrypt an existing password
#
# Project will be update @
# https://github.com/t3sl4/apg-tool
#
#

import os
import re
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
boolean = True


print '' + W
print '####################################'
print '#                                  #'
print '# APG tool                         #'
print '#                                  #'
print '# Advanced Password Generator Tool #'
print '#                                  #'
print '# By Tesla                         #'
print '#                                  #'
print '####################################'

def signal_handler(signal, frame):
  print ''
  print W + 'Quitting..' + N
  print ''
  sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def start_options():
  print ''
  print '[1] Generate Password'
  print '[2] Decrypt Password'
  print '[3] Quit'
  print ''

def start_char():
  print '' + W
  print '[d] Decimal'
  print '[l] Lowercase'
  print '[u] Uppercase'
  print '[s] Special'
  print '[r] Random'
  print ''
  schar = raw_input('Password start with: ' + N)
  return schar

def makepasswd():
  while boolean is True:
    block_size = raw_input(W + 'Choose block size [16,24,32]: ' + N)
    if block_size == '16':
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

  schar = start_char()
  dec = True
  while dec is True:
    decimal = raw_input(W + 'Number of decimals: ' + N)
    if decimal.isdigit():
      dec = False
  lcase = True
  while lcase is True:
    lowercase = raw_input(W + 'Number of lowercase: ' + N)
    if lowercase.isdigit():
      lcase = False
  ucase = True
  while ucase is True:
    uppercase = raw_input(W + 'Number of uppercase: ' + N)
    if uppercase.isdigit():
      ucase = False
  spec = True
  while spec is True:
    special_char = raw_input(W + 'Number of special char: ' + N)
    if special_char.isdigit():
      spec = False
  passwd_for = raw_input(W + 'Password for: ' + N)
  file_name = raw_input(W + 'File name: ' + N)

  while boolean is True:
    file_path = raw_input(W + 'File path: ' + N)
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
  if int(special_char) > 0:
    i = 0
    while i < int(special_char):
      passwd += ''.join(random.choice(string.punctuation))
      i += 1

  shuffle = list(passwd)
  random.shuffle(shuffle)
  passwd = ''.join(shuffle)
  if schar is 'd':
    cnt = 0
    passwd = list(passwd)
    for d in passwd:
      if d in string.digits:
        position = cnt
        break
      cnt += 1
    passwd.insert(0, passwd.pop(cnt))
    passwd = ''.join(passwd)
  elif schar is 'l':
    cnt = 0
    passwd = list(passwd)
    for d in passwd:
      if d in ascii_lowercase:
        position = cnt
        break
      cnt += 1
    passwd.insert(0, passwd.pop(cnt))
    passwd = ''.join(passwd)
  elif schar is 'u':
    cnt = 0
    passwd = list(passwd)
    for u in passwd:
      if u in ascii_uppercase:
        position = cnt
        break
      cnt += 1
    passwd.insert(0, passwd.pop(cnt))
    passwd = ''.join(passwd)
  elif schar is 's':
    cnt = 0
    passwd = list(passwd)
    for s in passwd:
      if s in string.punctuation:
        print s
        print cnt
        position = cnt
        break
      cnt += 1
    passwd.insert(0, passwd.pop(cnt))
    passwd = ''.join(passwd)
  else:
    print ''
  print W + 'Password: ' + G + passwd + N
  print ''

  ofile = open(file_path + file_name, 'a')
  if passwd_for is '':
    passwd_for = '<empty>'
  if file_name is '':
    file_name = 'apg-pass'
  padding1 = getpass.getpass(W + 'Padding [one char]: ')
  padding2 = getpass.getpass('Confirm Padding: ')
  key1 = getpass.getpass('Cipher Key [' + str(block_size) + ' char]: ')
  key2 = getpass.getpass('Confirm Cipher Key: ')
  pad = lambda s: s + (block_size - len(s) % block_size) * padding1
  encAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
  cipher = AES.new(key1)
  encoded = encAES(cipher, passwd)
  ofile.write(passwd_for + '::' + encoded + '\n')
  ofile.close()

  print ''
  print 'Done!'
  print ''

def decryptpasswd():
  pass_enc = raw_input(W + 'Passwd to decode: ' + N)
  padding = getpass.getpass(W + 'Padding: ')
  decAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(padding)

  key = getpass.getpass('Cipher Key: ')
  cipher = AES.new(key)
  decoded = decAES(cipher, pass_enc)
  print 'Decrypted Passwd: ' + G + decoded

while boolean is True:
  start_options()
  case = raw_input('Please Select: ' + N)
  if case is '1':
    print ''
    makepasswd()
  elif case is '2':
    print ''
    decryptpasswd()
  elif case is '3':
    print ''
    print W + 'Bye!' + N
    print ''
    exit(0)
  else:
    print R + 'Wrong Choice!' + W
