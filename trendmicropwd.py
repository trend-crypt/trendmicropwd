#!/usr/bin/python3
#
# Nearly all work done originally by
#     Copyright 2008 Luigi Auriemma
# Oringial C file available from
# http://www.aluigi.altervista.org/pwdrec.htm
#
# Ported to Python and added support
# for CRYPTCSTEX and CRYPTNG|CRYPTNGS formats
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
import base64
import hashlib
from Crypto.Cipher import AES

# Unpad function sourced from the following URL
# https://stackoverflow.com/questions/12524994/encrypt-and-decrypt-using-pycrypto-aes-256
# Cryptodome supplies one but it errors when decrypting empty strings
unpad = lambda s: s[:-ord(s[len(s)-1:])]

# Globals for CRYPTNG and CRYPTCSTEX
DATETIME = ''
NGKEY = ''
NGIV = ''

# Simplification of the original hex2byte
def hex2byte(hexstring):
    return bytes.fromhex(hexstring)

# Case insensitive pattern search in string
# Just here to look like the original code
def stristr(string, pattern):
    if re.search(pattern, string, re.IGNORECASE):
        return True
    else:
        return False

# Not actually strncmp, just making it look like
# the original code
def strncmp(string, pattern):
    if string.startswith(pattern):
        return string.split(pattern)[1]
    return 0

def trendmicro_build_key(pwd1, pwd2):
    pwd1 = pwd1.encode('utf-8')
    pwd2 = pwd2.encode('utf-8')
    out = [0] * 8
    for i in range(8):
        out[i] = i + 1

    x = 0x7f3b
    for i in range(4):
        x ^= ((pwd1[i] | (pwd2[i] << 8)) ^ 0x6b2c)

        t = i
        if i == 1:
            t = 2
        elif i == 2:
            t = 1
        out[(t*2)] ^= (x & 0xff)
        out[(t*2)+1] ^= (x & 0xff00) >> 8

    # b'\x41\x40\x44\x5d\x00\x46\x08\x4f'
    return out

def trendmicro_crypt1(key):
    table1  = b'\x07\x01\x06\x01\x05\x01\x04\x01\x03\x01\x02\x01\x01\x01\x00\x01'
    table1 += b'\x07\x02\x06\x02\x05\x02\x04\x02\x03\x02\x02\x02\x01\x02\x00\x02'
    table1 += b'\x07\x04\x06\x04\x05\x04\x04\x04\x03\x04\x02\x04\x01\x04\x00\x04'
    table1 += b'\x07\x08\x06\x08\x05\x08\x04\x08\x07\x40\x06\x40\x05\x40\x04\x40'
    table1 += b'\x03\x40\x02\x40\x01\x40\x00\x40\x07\x20\x06\x20\x05\x20\x04\x20'
    table1 += b'\x03\x20\x02\x20\x01\x20\x00\x20\x07\x10\x06\x10\x05\x10\x04\x10'
    table1 += b'\x03\x10\x02\x10\x01\x10\x00\x10\x03\x08\x02\x08\x01\x08\x00\x08'

    table2  = b'\x01\x01\x02\x02\x02\x02\x02\x02\x01\x02\x02\x02\x02\x02\x02\x01'

    table3  = b'\x0d\x10\x0a\x17\x00\x04\x02\x1b\x0e\x05\x14\x09\x16\x12\x0b\x03'
    table3 += b'\x19\x07\x0f\x06\x1a\x13\x0c\x01\x28\x33\x1e\x24\x2e\x36\x1d\x27'
    table3 += b'\x32\x2c\x20\x2f\x2b\x30\x26\x37\x21\x34\x2d\x29\x31\x23\x1c\x1f'
    tablex = [0] * 0x768
    tmp = [0] * 0x38

    for i in range(0x38):
        tmp[i] = 1 if (key[table1[i*2]] & table1[(i*2)+1]) else 0

    r = 0
    c = 0
    for i in range(0x10):
        c += table2[i]
        for j in range(0x30):
            t = table3[j]
            if (t < 0x1c):
                r = 0
            else:
                r = 0x1c
                t -= 0x1c
            t += c
            if (t >= 0x1c):
                t -= 0x1c
            t += r
            tablex[(i*0x30)+j] = tmp[t]

    return tablex

def trendmicro_crypt2(tablex, data, encdec):
    table1  = b'\x07\x02\x06\x02\x05\x02\x04\x02\x03\x02\x02\x02\x01\x02\x00\x02'
    table1 += b'\x07\x08\x06\x08\x05\x08\x04\x08\x03\x08\x02\x08\x01\x08\x00\x08'
    table1 += b'\x07\x20\x06\x20\x05\x20\x04\x20\x03\x20\x02\x20\x01\x20\x00\x20'
    table1 += b'\x07\x80\x06\x80\x05\x80\x04\x80\x03\x80\x02\x80\x01\x80\x00\x80'
    table1 += b'\x07\x01\x06\x01\x05\x01\x04\x01\x03\x01\x02\x01\x01\x01\x00\x01'
    table1 += b'\x07\x04\x06\x04\x05\x04\x04\x04\x03\x04\x02\x04\x01\x04\x00\x04'
    table1 += b'\x07\x10\x06\x10\x05\x10\x04\x10\x03\x10\x02\x10\x01\x10\x00\x10'
    table1 += b'\x07\x40\x06\x40\x05\x40\x04\x40\x03\x40\x02\x40\x01\x40\x00\x40'

    table2  = b'\x1f\x00\x01\x02\x03\x04\x03\x04\x05\x06\x07\x08\x07\x08\x09\x0a'
    table2 += b'\x0b\x0c\x0b\x0c\x0d\x0e\x0f\x10\x0f\x10\x11\x12\x13\x14\x13\x14'
    table2 += b'\x15\x16\x17\x18\x17\x18\x19\x1a\x1b\x1c\x1b\x1c\x1d\x1e\x1f\x00'

    table3  = b'\x0e\x04\x0d\x01\x02\x0f\x0b\x08\x03\x0a\x06\x0c\x05\x09\x00\x07'
    table3 += b'\x00\x0f\x07\x04\x0e\x02\x0d\x01\x0a\x06\x0c\x0b\x09\x05\x03\x08'
    table3 += b'\x04\x01\x0e\x08\x0d\x06\x02\x0b\x0f\x0c\x09\x07\x03\x0a\x05\x00'
    table3 += b'\x0f\x0c\x08\x02\x04\x09\x01\x07\x05\x0b\x03\x0e\x0a\x00\x06\x0d'
    table3 += b'\x0f\x01\x08\x0e\x06\x0b\x03\x04\x09\x07\x02\x0d\x0c\x00\x05\x0a'
    table3 += b'\x03\x0d\x04\x07\x0f\x02\x08\x0e\x0c\x00\x01\x0a\x06\x09\x0b\x05'
    table3 += b'\x00\x0e\x07\x0b\x0a\x04\x0d\x01\x05\x08\x0c\x06\x09\x03\x02\x0f'
    table3 += b'\x0d\x08\x0a\x01\x03\x0f\x04\x02\x0b\x06\x07\x0c\x00\x05\x0e\x09'
    table3 += b'\x0a\x00\x09\x0e\x06\x03\x0f\x05\x01\x0d\x0c\x07\x0b\x04\x02\x08'
    table3 += b'\x0d\x07\x00\x09\x03\x04\x06\x0a\x02\x08\x05\x0e\x0c\x0b\x0f\x01'
    table3 += b'\x0d\x06\x04\x09\x08\x0f\x03\x00\x0b\x01\x02\x0c\x05\x0a\x0e\x07'
    table3 += b'\x01\x0a\x0d\x00\x06\x09\x08\x07\x04\x0f\x0e\x03\x0b\x05\x02\x0c'
    table3 += b'\x07\x0d\x0e\x03\x00\x06\x09\x0a\x01\x02\x08\x05\x0b\x0c\x04\x0f'
    table3 += b'\x0d\x08\x0b\x05\x06\x0f\x00\x03\x04\x07\x02\x0c\x01\x0a\x0e\x09'
    table3 += b'\x0a\x06\x09\x00\x0c\x0b\x07\x0d\x0f\x01\x03\x0e\x05\x02\x08\x04'
    table3 += b'\x03\x0f\x00\x06\x0a\x01\x0d\x08\x09\x04\x05\x0b\x0c\x07\x02\x0e'
    table3 += b'\x02\x0c\x04\x01\x07\x0a\x0b\x06\x08\x05\x03\x0f\x0d\x00\x0e\x09'
    table3 += b'\x0e\x0b\x02\x0c\x04\x07\x0d\x01\x05\x00\x0f\x0a\x03\x09\x08\x06'
    table3 += b'\x04\x02\x01\x0b\x0a\x0d\x07\x08\x0f\x09\x0c\x05\x06\x03\x00\x0e'
    table3 += b'\x0b\x08\x0c\x07\x01\x0e\x02\x0d\x06\x0f\x00\x09\x0a\x04\x05\x03'
    table3 += b'\x0c\x01\x0a\x0f\x09\x02\x06\x08\x00\x0d\x03\x04\x0e\x07\x05\x0b'
    table3 += b'\x0a\x0f\x04\x02\x07\x0c\x09\x05\x06\x01\x0d\x0e\x00\x0b\x03\x08'
    table3 += b'\x09\x0e\x0f\x05\x02\x08\x0c\x03\x07\x00\x04\x0a\x01\x0d\x0b\x06'
    table3 += b'\x04\x03\x02\x0c\x09\x05\x0f\x0a\x0b\x0e\x01\x07\x06\x00\x08\x0d'
    table3 += b'\x04\x0b\x02\x0e\x0f\x00\x08\x0d\x03\x0c\x09\x07\x05\x0a\x06\x01'
    table3 += b'\x0d\x00\x0b\x07\x04\x09\x01\x0a\x0e\x03\x05\x0c\x02\x0f\x08\x06'
    table3 += b'\x01\x04\x0b\x0d\x0c\x03\x07\x0e\x0a\x0f\x06\x08\x00\x05\x09\x02'
    table3 += b'\x06\x0b\x0d\x08\x01\x04\x0a\x07\x09\x05\x00\x0f\x0e\x02\x03\x0c'
    table3 += b'\x0d\x02\x08\x04\x06\x0f\x0b\x01\x0a\x09\x03\x0e\x05\x00\x0c\x07'
    table3 += b'\x01\x0f\x0d\x08\x0a\x03\x07\x04\x0c\x05\x06\x0b\x00\x0e\x09\x02'
    table3 += b'\x07\x0b\x04\x01\x09\x0c\x0e\x02\x00\x06\x0a\x0d\x0f\x03\x05\x08'
    table3 += b'\x02\x01\x0e\x07\x04\x0a\x08\x0d\x0f\x0c\x09\x00\x03\x05\x06\x0b'

    table4  = b'\x0f\x06\x13\x14\x1c\x0b\x1b\x10\x00\x0e\x16\x19\x04\x11\x1e\x09'
    table4 += b'\x01\x07\x17\x0d\x1f\x1a\x02\x08\x12\x0c\x1d\x05\x15\x0a\x03\x18'

    table5  = b'\x27\x07\x2f\x0f\x37\x17\x3f\x1f\x26\x06\x2e\x0e\x36\x16\x3e\x1e'
    table5 += b'\x25\x05\x2d\x0d\x35\x15\x3d\x1d\x24\x04\x2c\x0c\x34\x14\x3c\x1c'
    table5 += b'\x23\x03\x2b\x0b\x33\x13\x3b\x1b\x22\x02\x2a\x0a\x32\x12\x3a\x1a'
    table5 += b'\x21\x01\x29\x09\x31\x11\x39\x19\x20\x00\x28\x08\x30\x10\x38\x18'
    tmp = [0] * 0x60
    tmp2 = [0] * 0x30
    bck = [0] * 0x20

    for i in range(0x40):
        tmp[i] = 1 if (data[table1[i*2]] & table1[(i*2)+1]) else 0

    t = 0
    for i in range(0x10):
        # memcpy(bck, tmp+0x20, 0x20)
        bck[0:0x20] = tmp[0x20:0x40]
        if not encdec:
            t = i
        else:
            t = 0xf - i
        for j in range(0x30):
            tmp2[j] = tmp[0x20 + table2[j]] ^ tablex[(t*0x30)+j]
        for j in range(8):
            t = j * 6
            c = (tmp2[t] << 5) | (tmp2[t+1] << 3) | (tmp2[t+2] << 2) | (tmp2[t+3] << 1) | tmp2[t+4] | (tmp2[t+5] << 4)
            c = table3[(j << 6)+c]
            t = j << 2
            tmp[0x40 + t] = (c >> 3) & 1
            tmp[0x41 + t] = (c >> 2) & 1
            tmp[0x42 + t] = (c >> 1) & 1
            tmp[0x43 + t] = c & 1
        for j in range(0x20):
            tmp[0x20 + j] = tmp[j] ^ tmp[0x40 + table4[j]]
        # memcpy(tmp, bck, 0x20)
        tmp[0:0x20] = bck[0:0x20]

    # memcpy(bck, tmp+0x20, 0x20)
    bck[0:0x20] = tmp[0x20:0x40]
    # memcpy(tmp+0x20, tmp, 0x20)
    tmp[0x20:0x40] = tmp[0:0x20]
    # memcpy(tmp, bck, 0x20)
    tmp[0:0x20] = bck[0:0x20]

    t = 0
    for i in range(8):
        data[i] = 0
        for j in [1 << x for x in range(8)]:
            if (tmp[table5[t]]):
                data[i] |= j
            t += 1

    return data

def trendmicro_crypt(data):
    # Original code has this all in trendmicro_decrypt()
    # I've opted to move it to its own function to align with all the other types
    blocks = ord(data[0]) - 0x30 # First byte is a number indicating the number of blocks to decrypt
    length = int((data[1]+data[2]),16) # Second and third bytes are the length of the string
    if ((blocks > 8) or (length > 64)):
        return None
    data = data[3:]
    # Rather than call hex2byte multiple times, I'm calling here once
    data = hex2byte(data)

    key = trendmicro_build_key("Windows7621673NT", "Virus3761267Trend")

    tablex = trendmicro_crypt1(key)
    output = bytearray('', 'utf-8')
    for i in range(blocks):
        block = 8 * i
        tmp = bytearray(data[block:block+8])
        output += trendmicro_crypt2(tablex, tmp, 1)

    # Usually a CRC check here, not currently implemented
    output = output[3:].decode('utf-8').rstrip('\x00')
    return output

def trendmicro_PWDDecrypt(data):
    # Code is here for reference and has not been tested
    # Use the original C version if you need this
    # Static key
    key = "199802232"
    tables = 3
    tablesz = 0x48
    tmp = []
    table = []

    # Table 1
    c = 0
    length = len(key)
    for i in range(tablesz):
        c += (key[i % length] + i) * 17
        tmp[i] = key[(i + 1) % length] + (key[i % length] * c)

    # Table 2
    j = 0
    length = (tablesz - tables) / tables
    for i in range(tables):
        table[i]['data']   = tmp[j]
        table[i]['datasz'] = length
        table[i]['n']      = 0
        j += length
        length += 1

    data = hex2byte(data)
    length = len(data)
    for i in range(length):
        c = 0
        for j in range(tables):
            c ^= table[j]['data'][table[j]['n']]
            table[j]['n'] += 1
            if (table[j]['n'] == table[j]['datasz']):
                table[j]['n'] = 0
        data[i] ^= c

    return data.decode('utf-8')

def trendmicro_cryptex(data):
    # Static key and IV, see README for details
    key = b'\xeb\x06\xe9\xc7\x6c\x16\x1d\x6c\x89\x70\x3d\xfc\x72\x53\xff\xdd\x71\xad\x07\xbf\x12\xf4\xa2\xe7\xa0\x89\xfc\x7c\xa6\xca\x4b\x73'
    iv = b'\x15\x69\x2e\xfc\x39\x89\x4a\xba\x9b\x62\xce\x66\xc9\x05\x12\xae'

    data = hex2byte(data)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(data))
    return decrypted[3:].decode('utf-8')

def trendmicro_cryptcst(data):
    if (DATETIME == ''):
        return "--- CRYPTCSTEX string found but InstallDateTime not set!"
    key = DATETIME.encode('utf-8')
    key = hashlib.sha1(key).hexdigest().upper()
    key = key[0:32].encode('utf-8')
    # Static IV, see README for details
    iv = b'\x17\x6c\x2a\xf2\x10\x86\x47\x7c\x7d\x5f\xc9\x64\xdd\x05\x38\x79'

    # Trend doesn't properly pad these
    # so we'll do it for them
    data = base64.b64decode(data + '==')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(data))
    return decrypted[3:].decode('utf-8')

def trendmicro_cryptng(data, **kwargs):
    # Same as cryptex but key and IV must be supplied, see README
    if (NGKEY == ''):
        return "--- CRYPTNG string found but key not set!"
    key = NGKEY.encode('utf-8')
    iv = NGIV.encode('utf-8')
    data = hex2byte(data)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted = unpad(cipher.decrypt(data))
        return decrypted[3:].decode('utf-8')
    except ValueError:
        return "None (Decrypted value may just be blank)"

def trendmicro_decrypt(string):
    string = string.strip()
    if (data := strncmp(string, '!CRYPT!')):
        output = ''
        for chunk in (data.split('!')):
          output += trendmicro_crypt(chunk)
        return output
    elif (data := strncmp(string, '!CRYPTEX!')):
        return trendmicro_cryptex(data)
    elif (data := strncmp(string, '!CRYPTEX3!')):
        return trendmicro_cryptex(data)
    elif (data := strncmp(string, '!CRYPTCSTEX!')):
        return trendmicro_cryptcst(data)
    elif (data := strncmp(string, '!CRYPTNG!')):
        return trendmicro_cryptng(data)
    elif (data := strncmp(string, '!CRYPTNGS!')):
        return trendmicro_cryptng(data)
    else:
        return trendmicro_PWDDecrypt(data)

    return

def main():
    print("""
TrendMicro passwords decryptor (2023.10.22)
original work by Luigi Auriemma (aluigi.org)
""")

    if (len(sys.argv) < 2):
        print("""
Usage: %s [file.ini/password]

Automatically decrypts any password in the input file
It supports: !CRYPT!, !CRYPTEX!, !CRYPTEX3!
             !CRYPTCSTEX!, !CRYPTNG!, !CRYPTNGS!,
             and the PWD.DLL!PWDDecrypt strings.
Note that some values decrypt to hashes that will need to be cracked.
""" % (sys.argv[0]))
        return

    found = 0
    fname = sys.argv[1]
    with open(fname, 'r') as file:
        for line in file.readlines():
            line = line.rstrip()
            if line.startswith('#'):
                continue
            if (stristr(line, "InstallDateTime")):
                global DATETIME
                DATETIME = line.split('=')[1]
                print("*** Got InstallDateTime for CSTEX: {}".format(DATETIME))
            elif (stristr(line, "skos")):
                keys = line.split('=')[1]
                global NGKEY
                NGKEY = keys[0:32]
                global NGIV
                NGIV = keys[32:48]
                print("*** Got NGKEY and NGIV from file: {} + {}".format(NGKEY, NGIV))
            elif (stristr(line, "pwd") or stristr(line, "pass") or stristr(line, "!CRYPT")):
                key, value = line.split('=')
                key = key.strip()
                decrypted = trendmicro_decrypt(value)
                print("%s = %s" % (key, decrypted))
                found += 1

    if (found == 0):
        print("No passwords found!")
    return

if __name__ == "__main__":
    main()
