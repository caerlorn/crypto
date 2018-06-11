#!/usr/bin/env python

import hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder


# def intToBytestring(*args):  # was just testing overloaded funcs since it seems python doesn't allow it like Java
#     s = ''
#     if len(args) == 1 and isinstance(args[0], int):
#         i = args[0]
#         if not i:
#             return chr(0x00)
#         else:
#             while i > 0:
#                 s = chr(i & 0xff) + s
#                 i = i >> 8
#             return s
#     elif len(args) == 2 and isinstance(args[0], int) and isinstance(args[1], int):
#         i = args[0]
#         length = args[1]
#         for smth in xrange(length):
#             s = chr(i & 0xff) + s
#             i >>= 8
#         return s
#     pass

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


def bytestring_to_int(s):
    # converts bytestring to integer
    i = 0
    for char in s:
        i <<= 8
        i |= ord(char)
    return i


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


def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    pemEncoded = ''
    derEncoded = None
    if 'BEGIN PUBLIC KEY' in content:
        pemEncoded = content[27:]
        pemEncoded = pemEncoded[:-26]
        derEncoded = pemEncoded.decode('base64')
        return derEncoded
    elif 'BEGIN RSA PRIVATE KEY' in content:
        pemEncoded = content[32:]
        pemEncoded = pemEncoded[:-31]
        derEncoded = pemEncoded.decode('base64')
        return derEncoded
    else:
        return content


def get_pubkey(filename):
    # reads public key file and returns (n, e)
    pubkey = []
    pemKey = ''
    derKey = ''
    with open(filename, 'rb') as p:
        pemKey = p.read()
    p.close()
    derKey = pem_to_der(pemKey)
    toBitStr = decoder.decode(derKey)[0][1]
    toStr = ''.join('%s' % i for i in toBitStr)
    toInt = int(toStr, 2)
    toByteStr = intToBytestring(toInt)
    pubkey.append(decoder.decode(toByteStr)[0][0])
    pubkey.append(decoder.decode(toByteStr)[0][1])
    return int(pubkey[0]), int(pubkey[1])


def get_privkey(filename):
    # reads private key file and returns (n, d)
    privkey = []
    derKey = ''
    pemKey = ''
    with open(filename, 'rb') as p:
        pemKey = p.read()
    p.close()
    derKey = pem_to_der(pemKey)
    privkey = decoder.decode(derKey)
    return int(privkey[0][1]), int(privkey[0][3])


def pkcsv15pad_encrypt(plaintext, n):
    # pad plaintext for encryption according to PKCS#1 v1.5
    plain = ''
    # calculate byte size of the modulus n
    nLen = len(intToBytestring(n))
    with open(plaintext, 'rb') as p:
        plain = p.read()
    p.close()
    # plaintext must be at least 11 bytes smaller than modulus
    if len(plain) <= nLen - 11:
        padBytes = nLen - (len(plain) + 3)
        pad = os.urandom(padBytes)
        while chr(0x00) in pad:
            pad = os.urandom(padBytes)
        padded_plaintext = ''.join(['\x00\x02', pad, '\x00', plain])
    else:
        print 'File too big!'
        #print ('%i bytes needed for message, but there is only space for %i' % (len(plain), nLen - 11))
        sys.exit(1)
    # generate padding bytes
    return padded_plaintext


def pkcsv15pad_sign(plaintext, n):
    # pad plaintext for signing according to PKCS#1 v1.5
    padded_plaintext = ''
    # calculate byte size of modulus n
    nLen = len(intToBytestring(n))
    # plaintext must be at least 3 bytes smaller than modulus
    if len(plaintext) <= nLen - 3:
        padBytes = nLen - (len(plaintext) + 3)
        padded_plaintext = ''.join(['\x00\x01', padBytes * '\xff', '\x00', plaintext])
    else:
        print 'Signing error'
        sys.exit(1)
    # generate padding bytes
    return padded_plaintext


def pkcsv15pad_remove(plaintext):
    # removes PKCS#1 v1.5 padding
    plain = None
    indexPos = plaintext.find(chr(0x00))
    plain = plaintext[1:]
    plaintext = plain[indexPos:]
    return plaintext


def encrypt(keyfile, plaintextfile, ciphertextfile):
    pubKey = get_pubkey(keyfile)
    paddedPlainTxt = pkcsv15pad_encrypt(plaintextfile, pubKey[0])
    m = bytestring_to_int(paddedPlainTxt)
    cipherTxt = pow(m, pubKey[1], pubKey[0])
    cipherTxt = intToBytestring(cipherTxt)
    with open(ciphertextfile, 'w+') as p:
        p.write(cipherTxt)
    p.close()
    pass


def decrypt(keyfile, ciphertextfile, plaintextfile):
    privKey = []
    c = ''
    m = ''
    with open(ciphertextfile, 'rb') as p:
        c = p.read()
    p.close()
    c = bytestring_to_int(c)
    privKey = get_privkey(keyfile)
    m = pow(c, privKey[1], privKey[0])
    m = intToBytestring(m)
    m = pkcsv15pad_remove(m)
    with open(plaintextfile, 'w+') as p:
        p.write(m)
    p.close()
    pass


def digestinfo_der(filename):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA256 digest of file
    der = ''
    digestHash = hashlib.sha256()
    with open(filename, 'rb') as p:
        while True:
            fileData = p.read(1024)
            if not fileData:
                break
            digestHash.update(fileData)
    p.close()
    der = asn1_sequence(asn1_sequence(asn1_objectidentifier([2, 16, 840, 1, 101, 3, 4, 2, 1]) + asn1_null())
                        + asn1_octetstring(digestHash.digest()))
    return der


def sign(keyfile, filetosign, signaturefile):
    # Warning: make sure that signaturefile produced has the same
    # byte size as the modulus (hint: use parametrized int_to_bytestring()).
    privKey = []
    plainTxt = ''
    byteStr = ''
    digest = ''
    privKey = get_privkey(keyfile)
    digest = digestinfo_der(filetosign)
    plainTxt = pkcsv15pad_sign(digest, privKey[0])
    plainTxt = bytestring_to_int(plainTxt)
    byteStr = pow(plainTxt, privKey[1], privKey[0])
    byteStr = intToBytestring(byteStr)
    nLen = len(intToBytestring(privKey[0]))
    if len(byteStr) < nLen:
        byteStr = chr(0x00) * (nLen - len(byteStr)) + byteStr
    with open(signaturefile, 'w+') as p:
        p.write(byteStr)
    p.close()
    pass


def verify(keyfile, signaturefile, filetoverify):
    # prints "Verified OK" or "Verification Failure"
    pubKey = get_pubkey(keyfile)
    s = ''
    m = ''
    with open(signaturefile, 'rb') as p:
        s = p.read()
    p.close()
    s = bytestring_to_int(s)
    m = pow(s, pubKey[1], pubKey[0])
    m = intToBytestring(m)
    m = pkcsv15pad_remove(m)
    digestHash = hashlib.sha256()
    with open(filetoverify, 'rb') as p:
        while True:
            fileData = p.read(1024)
            if not fileData:
                break
            digestHash.update(fileData)
    p.close()
    digest = decoder.decode(m)[0][1]
    digestCalc = digestHash.digest()
    if digest != digestCalc:
        print "[-] Verification Failure"
    else:
        print "[+] Verified OK"
    pass


def usage():
    print "Usage:"
    print "encrypt <public key file> <plaintext file> <output ciphertext file>"
    print "decrypt <private key file> <ciphertext file> <output plaintext file>"
    print "sign <private key file> <file to sign> <signature output file>"
    print "verify <public key file> <signature file> <file to verify>"
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'sign':
    sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
