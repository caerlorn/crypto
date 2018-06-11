#!/usr/bin/python

import datetime, os, sys
from pyasn1.codec.der import decoder

# $ sudo apt-get install python-crypto
sys.path = sys.path[1:] # removes script directory from aes.py search path
from Crypto.Cipher import AES          # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.AES-module.html
from Crypto.Protocol.KDF import PBKDF2 # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Protocol.KDF-module.html#PBKDF2
from Crypto.Util.strxor import strxor  # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Util.strxor-module.html#strxor
import hashlib, hmac # do not use any other imports/libraries


def intToBytestring(i):
    s = ''
    if not i:
        return chr(0x00)
    else:
        while i > 0:
            s = chr(i & 0xff) + s
            i = i >> 8
        return s


def intToBase128Bytestring(i):
    first_remainder = True
    s = ''
    quotient = i
    remainder = 0

    while quotient:
        remainder = quotient % 0x80
        quotient = quotient // 0x80
        if first_remainder:
            s = chr(remainder) + s
            first_remainder = False
        else:
            s = chr(0x80 | remainder) + s
    return s


def asn1_len(content_str):
    # helper function - should be used in other functions to calculate length octet(s)
    # content - bytestring that contains TLV content octet(s)
    # returns length (L) octet(s) for TLV
    if len(content_str) <= 0x7f:
        return chr(len(content_str))
    else:
        contentStrLen = len(content_str)
        contentStrBytes = intToBytestring(contentStrLen)
        return chr(0x80 | len(contentStrBytes)) + contentStrBytes
    pass


def asn1_boolean(bool):
    # BOOLEAN encoder has been implemented for you
    if bool:
        bool = chr(0xff)
    else:
        bool = chr(0x00)
    return chr(0x01) + asn1_len(bool) + bool


def asn1_null():
    # returns DER encoding of NULL
    return chr(0x05) + chr(0x00)
    pass


def asn1_integer(i):
    # i - arbitrary integer (of type 'int' or 'long')
    # returns DER encoding of INTEGER
    iBytes = intToBytestring(i)
    if not i:
        return chr(0x02) + asn1_len(chr(0x00)) + chr(0x00)
    elif ord(iBytes[0]) & 0x80:
        return chr(0x02) + asn1_len(chr(0x00) + iBytes) + chr(0x00) + iBytes
    else:
        return chr(0x02) + asn1_len(iBytes) + iBytes
    pass


def asn1_bitstring(bitstr):
    # bitstr - bytestring containing bitstring (e.g., "10101")
    # returns DER encoding of BITSTRING
    pad_len = 8 - len(bitstr) % 8
    if pad_len == 8:
        pad_len = 0
    bitstr += "0" * pad_len
    i = 0
    for bit in bitstr:
        i = i << 1
        if bit == '1':
            i = i | 1
    length_in_bytes = (len(bitstr) + 7) / 8
    s = ""
    for _ in xrange(length_in_bytes):
        s = chr(i & 0b11111111) + s
        i = i >> 8
    s = chr(pad_len) + s
    return chr(0b00000011) + asn1_len(s) + s


def asn1_octetstring(octets):
    # octets - arbitrary byte string (e.g., "abc\x01")
    # returns DER encoding of OCTETSTRING
    return chr(0x04) + asn1_len(octets) + octets
    pass


def asn1_objectidentifier(oid):
    # oid - list of integers representing OID (e.g., [1,2,840,123123])
    # returns DER encoding of OBJECTIDENTIFIER
    oidFb = intToBytestring(oid[0] * 40 + oid[1])
    comp = ''
    for i in oid[2:]:
        comp += intToBase128Bytestring(i)
    return chr(0x06) + asn1_len(oidFb + comp) + oidFb + comp
    pass


def asn1_sequence(der):
    # der - DER bytestring to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    return chr(0x30) + asn1_len(der) + der
    pass


def asn1_set(der):
    # der - DER bytestring to encapsulate into set
    # returns DER encoding of SET
    return chr(0x31) + asn1_len(der) + der
    pass


def asn1_printablestring(string):
    # string - bytestring containing printable characters (e.g., "foo")
    # returns DER encoding of PrintableString
    return chr(0x13) + asn1_len(string) + string
    pass


def asn1_utctime(time):
    # time - bytestring containing timestamp in UTCTime format (e.g., "121229010100Z")
    # returns DER encoding of UTCTime
    return chr(0x17) + asn1_len(time) + time
    pass


def asn1_tag_explicit(der, tag):
    # der - DER encoded bytestring
    # tag - tag value to specify in the type octet
    # returns DER encoding of original DER that is encapsulated in tag type
    return chr(0xa0 | tag) + asn1_len(der) + der
    pass


# this function benchmarks how many PBKDF2 iterations
# can be performed in one second on the machine it is executed
def benchmark():
    # measure time for performing 10000 iterations
    startTime = datetime.datetime.now()
    keyPass = PBKDF2('hebele', os.urandom(8), 36, 10000)
    stopTime = datetime.datetime.now()
    time = (stopTime - startTime).total_seconds()
    # extrapolate to 1 second
    iter = 10000 // time
    print "[+] Benchmark: %s PBKDF2 iterations in 1 second" % (iter)
    return iter # returns number of iterations that can be performed in 1 second


def cbcEnc(nonce, keyAES, pfile):
    chunkLoop = True
    aesObject = AES.new(keyAES)
    cipherTxt = ''
    xorResult = ''
    BS = 16     # Was going to get as a parameter and try in the below lambda function but had problems
    # pad = lambda fileData: fileData + (BS - len(fileData) % BS) * chr(BS - len(fileData) % BS)
    with open(pfile, 'r') as p:
        while True:
            fileData = p.read(BS)
            pad = BS - len(fileData)
            if not chunkLoop:
                break
            elif 0 < pad < BS:
                fileData = fileData + (chr(pad) * pad)
                chunkLoop = False
            elif not fileData:
                fileData = chr(BS) * BS
                chunkLoop = False
            xorResult = strxor(nonce, fileData)
            nonce = aesObject.encrypt(xorResult)
            cipherTxt += aesObject.encrypt(xorResult)
    p.close()
    return cipherTxt
    pass


def cbcDec(nonce, keyAES, cfile, initPos):
    aesObject = AES.new(keyAES)
    plainTxt = ''
    cipherTxt = ''
    pad = ''
    #unpad = lambda fileData : fileData[:-ord(fileData[len(fileData)-1:])]
    with open(cfile, 'r') as p:
        p.seek(initPos)
        while True:
            fileData = p.read(16)
            if not fileData:
                break
            cipherTxt = fileData
            dec = aesObject.decrypt(cipherTxt)
            plainTxt += strxor(nonce, dec)
            nonce = cipherTxt
    p.close()
    return plainTxt[:-ord(plainTxt[-1])]
    pass

def encrypt(pfile, cfile):
    chunkLoop = True

    # benchmarking
    iter = benchmark()

    # asking for password
    print "[?] Enter password:",
    password = raw_input()

    # deriving key
    nonce = os.urandom(16)
    salt = os.urandom(8)
    keyLen = 36
    keyPass = PBKDF2(password, salt, keyLen, int(iter))
    keyAES = keyPass[:16]
    keyHMAC = keyPass[16:]
    cipherTxt = cbcEnc(nonce, keyAES, pfile)

    # writing ciphertext in temporary file and calculating HMAC digest
    with open(cfile + '.tmp', "w+") as p:  # I figure it is bad practice to create this file in the same directory
        p.write(cipherTxt)                   # but Windows gives me a headache when I try to write in another directory
    p.close()
    macer = hmac.new(keyHMAC, None, hashlib.sha1)
    with open(cfile + '.tmp', 'r') as p:
         while chunkLoop:
            data_chunk = p.read(512)
            if not data_chunk:
                chunkLoop = False
            macer.update(data_chunk)
    p.close()

    # writing DER structure in cfile
    asn = asn1_sequence(asn1_sequence(asn1_octetstring(salt) + asn1_integer(int(iter)) + asn1_integer(keyLen))
                        + asn1_sequence(asn1_objectidentifier([2, 16, 840, 1, 101, 3, 4, 1, 2])
                            + asn1_octetstring(nonce))
                        + asn1_sequence(asn1_sequence(asn1_objectidentifier([1, 3, 14, 3, 2, 26]) + asn1_null())
                            + asn1_octetstring(macer.digest())))
    #print len(asn)

    # writing temporary ciphertext file to cfile
    with open(cfile, 'w+') as p:
        p.write(asn)
        with open(cfile + '.tmp', 'r') as y:
            for x in y:
                p.write(x)
        y.close()
    p.close()

    # deleting temporary ciphertext file
    os.remove(cfile + '.tmp')
    pass


def decrypt(cfile, pfile):
    # reading DER structure
    with open(cfile, 'r') as p:
        fileData = p.read()
    p.close()
    nonce = str(decoder.decode(fileData)[0][1][1])
    salt = str(decoder.decode(fileData)[0][0][0])
    keyLen = int(decoder.decode(fileData)[0][0][2])
    iter = int(decoder.decode(fileData)[0][0][1])
    digest = decoder.decode(fileData)[0][2][1]
    cipherInit = 0x5D - ord(asn1_len(asn1_integer(iter)))
    #print len(nonce)
    #print len(salt)
    #print keyLen
    #print iter
    #print cipherInit

    # asking for password
    print "[?] Enter password:",
    password = raw_input()

    # deriving key
    keyPass = PBKDF2(password, salt, keyLen, int(iter))
    keyAES = keyPass[:16]
    keyHMAC = keyPass[16:]

    # first pass over ciphertext to calculate and verify HMAC
    macer = hmac.new(keyHMAC, None, hashlib.sha1)
    with open(cfile, 'r') as p:
        p.seek(cipherInit)
        while True:
            fileData = p.read(512)
            if not fileData:
                break
            macer.update(fileData)
    p.close()
    fileDigest = macer.digest()
    if fileDigest != digest:
        print "[-] Wrong key or message has been manipulated!"
    else:
        print "[+] HMAC verification successful!"
    # second pass over ciphertext to decrypt
        plainTxt = cbcDec(nonce, keyAES, cfile, cipherInit)
        with open(pfile, 'w+') as p:
            p.write(plainTxt)
        p.close()
    pass

def usage():
    print "Usage:"
    print "-encrypt <plaintextfile> <ciphertextfile>"
    print "-decrypt <ciphertextfile> <plaintextfile>"
    sys.exit(1)


if len(sys.argv) != 4:
    usage()
elif sys.argv[1] == '-encrypt':
    encrypt(sys.argv[2], sys.argv[3])
elif sys.argv[1] == '-decrypt':
    decrypt(sys.argv[2], sys.argv[3])
else:
    usage()
