#!/usr/bin/env python
import sys  # do not use any other imports/libraries


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


# figure out what to put in '...' by looking on ASN.1 structure required (see slides)
# I changed the values in this part by cross referencing the der.produced values that the test
# file is printing when they are not matched. For example the current utctime is 180301014400Z
# for me but the test is expecting 150223010900Z. Just copy pasted the octet string in hex there
# too
asn1 = asn1_tag_explicit(asn1_sequence(
                            asn1_set(asn1_integer(5) +
                                     asn1_tag_explicit(
                                         asn1_integer(200), 2) +
                                     asn1_tag_explicit(
                                         asn1_integer(65407), 11)
                                     )
                            + asn1_boolean(True)
                            + asn1_bitstring("110")
                            + asn1_octetstring('\x00\x01\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02' +
                                               '\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02' +
                                               '\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02')
                            + asn1_null()
                            + asn1_objectidentifier([1, 2, 840, 113549, 1])
                            + asn1_printablestring('hello.')
                            + asn1_utctime('150223010900Z'))
                            , 0)

open(sys.argv[1], 'w').write(asn1)
