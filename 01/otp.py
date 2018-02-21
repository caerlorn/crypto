#!/usr/bin/env python
import os, sys  # do not use any other imports/libraries


# I tried to fix the problems that I had last year
# Still took 7-8 hours (please specify here how much time your solution required)

def bytestring_to_int(s):
    # your implementation here
    i = []
    i = i.append([ord(x) for x in s])
    return i


def int_to_bytestring(i, length):
    # your implementation here
    s = []
    for j in range(0, length):
        s.append(i >> (j * 8) & 0xff)
    s.reverse()
    return s


def encrypt(pfile, kfile, cfile):
    # your implementation here
    with open(pfile, 'r') as p:
        pfile_data = p.read()
    p.close()
    pfile_int = bytestring_to_int(pfile_data)
    kfile_data = os.urandom(len(pfile_data))
    kfile_int = bytestring_to_int(kfile_data)
    cfile_int = pfile_int ^ kfile_int
    cfile_data = int_to_bytestring(cfile_int, len(cfile_int))
    key = int_to_bytestring(kfile_int, len(kfile_int))
    with open(kfile, 'w+') as p:
        p.write(key)
    p.close()
    with open(cfile, 'w+') as p:
        p.write(cfile_data)
    p.close()
    pass


def decrypt(cfile, kfile, pfile):
    # your implementation here
    with open(cfile, 'r') as p:
        cfile_data = p.read()
    p.close()
    cfile_int = bytestring_to_int(cfile_data)
    with open(kfile, 'r') as p:
        kfile_data = p.read()
    p.close()
    kfile_int = bytestring_to_int(kfile_data)
    pfile_int = cfile_int ^ kfile_int
    pfile_data = int_to_bytestring(pfile_int, len(pfile_int))
    with open(pfile, 'w+') as p:
        p.write(pfile_data)
    p.close()
    pass


def usage():
    print "Usage:"
    print "encrypt <plaintext file> <output key file> <ciphertext output file>"
    print "decrypt <ciphertext file> <key file> <plaintext output file>"
    sys.exit(1)


if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
