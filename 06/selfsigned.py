#!/usr/bin/env python

import argparse, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder

# http://www.umich.edu/~x509/ssleay/asn1-oids.html was really helpful for all the oid numbers

# parse arguments
parser = argparse.ArgumentParser(description='generate self-signed X.509 CA certificate', add_help=False)
parser.add_argument("private_key_file", help="Private key file (in PEM or DER form)")
parser.add_argument("output_cert_file", help="File to store self-signed CA certificate (PEM form)")
args = parser.parse_args()


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
    # reads private key file and returns (n, e)
    pubkey = []
    pemKey = ''
    derKey = ''
    with open(filename, 'rb') as p:
        pemKey = p.read()
    p.close()
    derKey = pem_to_der(pemKey)
    pubkey = decoder.decode(derKey)
    return int(pubkey[0][1]), int(pubkey[0][2])


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


def digestinfo_der(m):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA256 digest of m
    der = ''
    digestHash = hashlib.sha256()
    digestHash.update(m)
    der = asn1_sequence(asn1_sequence(asn1_objectidentifier([2, 16, 840, 1, 101, 3, 4, 2, 1]) + asn1_null())
                        + asn1_octetstring(digestHash.digest()))
    return der


def sign(m, keyfile):
    # sign DigestInfo of message m
    privKey = []
    c = ''
    digestInfo = ''
    plainTxt = ''
    privKey = get_privkey(keyfile)
    digestInfo = digestinfo_der(m)
    plainTxt = pkcsv15pad_sign(digestInfo, privKey[0])
    plainTxt = bytestring_to_int(plainTxt)
    c = pow(plainTxt, privKey[1], privKey[0])
    c = intToBytestring(c)
    nLen = len(intToBytestring(privKey[0]))
    if len(c) < nLen:
        c = chr(0x00) * (nLen - len(c)) + c
    return c


def selfsigned(privkey, certfile):
    # create x509v3 self-signed CA root certificate
    cert = ''
    pem = ''
    der = ''
    # get public key (n, e) from private key file
    n, e = get_pubkey(privkey)
    # construct subjectPublicKeyInfo from public key values (n, e)
    pubKeyInfoASN = asn1_sequence(asn1_integer(n) + asn1_integer(e))
    pubKeyInfoASN = ''.join('{:08b}'.format(ord(x), 'b') for x in pubKeyInfoASN)
    subjectPublicKeyInfo = asn1_sequence(
        asn1_sequence(asn1_objectidentifier([1, 2, 840, 113549, 1, 1, 1]) + asn1_null()) + asn1_bitstring(
            str(pubKeyInfoASN)))
    # construct tbsCertificate structure
    version = asn1_tag_explicit(asn1_integer(2), 0)
    serialNumber = asn1_integer(89)
    signature = asn1_sequence(asn1_objectidentifier([1, 2, 840, 113549, 1, 1, 11]) + asn1_null())
    country = asn1_sequence(asn1_objectidentifier([2, 5, 4, 6]) + asn1_printablestring('TR'))
    organization = asn1_sequence(asn1_objectidentifier([2, 5, 4, 10]) + asn1_printablestring('University of Tartu'))
    ou = asn1_sequence(asn1_objectidentifier([2, 5, 4, 11]) + asn1_printablestring('IT dep'))
    cn = asn1_sequence(asn1_objectidentifier([2, 5, 4, 3]) + asn1_printablestring('Yildirim Can CA'))
    issuer = asn1_sequence(asn1_set(country + organization + ou + cn))
    validity = asn1_sequence(asn1_utctime('171229000000Z') + asn1_utctime('181229000000Z'))
    subject = asn1_sequence(asn1_set(country + organization + ou + cn))
    basicConstraints = asn1_sequence(asn1_boolean(True))
    basicConstraintsExt = asn1_sequence(asn1_objectidentifier([2, 5, 29, 19]) + asn1_boolean(True)
                                         + asn1_octetstring(basicConstraints))
    keyUsage = '00000110'
    keyUsage = asn1_bitstring(keyUsage)
    keyUsageExt = asn1_sequence(asn1_objectidentifier([2, 5, 29, 15]) + asn1_boolean(True) + asn1_octetstring(keyUsage))
    extension = asn1_sequence(basicConstraintsExt + keyUsageExt)
    extensions = asn1_tag_explicit(extension, 3)
    tbsCertificate = asn1_sequence(version + serialNumber + signature + issuer + validity + subject
                                   + subjectPublicKeyInfo + extensions)
    # sign tbsCertificate structure
    signature = sign(tbsCertificate, privkey)
    signatureVal = ''.join('{:08b}'.format(ord(x), 'b') for x in signature)
    signatureVal = asn1_bitstring(signatureVal)
    signatureAlgo = asn1_sequence(asn1_objectidentifier([1, 2, 840, 113549, 1, 1, 11]) + asn1_null())
    # construct final X.509 DER
    cert = asn1_sequence(tbsCertificate + signatureAlgo + signatureVal)
    # convert to PEM by .encode('base64') and adding PEM headers
    pem = '-----BEGIN CERTIFICATE-----\n' + cert.encode('base64') + '-----END CERTIFICATE-----\n'
    # write PEM certificate to file
    with open(certfile, 'w+') as p:
        p.write(pem)
    p.close()


selfsigned(args.private_key_file, args.output_cert_file)
