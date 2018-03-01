#!/usr/bin/env python
import sys   # do not use any other imports/libraries

# took 13.0 hours (please specify here how much time your solution required)

# Looked at plethora of sources for both trying to understand the underlying logic and
# implementation techniques. I did not know if we were allowed to implement separate functions
# for bytestring conversions so I tried to do them inside the template functions; albeit rather poorly.


def asn1_len(content_str):
    # helper function - should be used in other functions to calculate length octet(s)
    # content - bytestring that contains TLV content octet(s)
    # returns length (L) octet(s) for TLV
    content_to_bs_length = len(content_str)
    str_i = ""
    if len(content_str) <= 127:
        return chr(len(content_str))
    elif not content_to_bs_length:
        str_i = chr(0x00)
        return chr(128 | str_i) + str_i
    else:
        while content_to_bs_length > 0:
            str_i = chr(content_to_bs_length & 255) + str_i
            content_to_bs_length = content_to_bs_length >> 8
        return chr(128 | str_i) + str_i
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
    if not i:
        return chr(0x02) + asn1_len(chr(0x00)) + chr(0x00)
    else:
        str_i = ""
        while i > 0:
            str_i = chr(i & 255) + str_i
            i = i >> 8
    if i >> ((len(str_i) * 8) - 1):
        return chr(0x02) + asn1_len(chr(0x00) + str_i) + chr(0x00) + str_i
    else:
        return chr(0x02) + asn1_len(str_i) + str_i
    pass


def asn1_bitstring(bitstr):
    # bitstr - bytestring containing bitstring (e.g., "10101")
    # returns DER encoding of BITSTRING
    der_bitstr = ""
    if bitstr == '':
        der_bitstr = chr(0x03) + asn1_len(chr(0x00)) + chr(0x00)
    else:
        bitstr_length = len(bitstr)
        pad = 0
        if bitstr_length % 8:
            pad = 8 - (bitstr_length % 8)
        bitstr_b = int(bitstr, 2)
        bitstr_padded = bitstr_b << pad
        if not bitstr_padded:
            der_bitstr = chr(0x00)
        else:
            while bitstr_padded > 0:
                der_bitstr = chr(bitstr_padded & 0xff) + der_bitstr
                bitstr_padded >>= 8
        der_bitstr = chr(0x03) + asn1_len(chr(pad) + der_bitstr) + chr(pad) + der_bitstr
    return der_bitstr
    pass


def asn1_octetstring(octets):
    # octets - arbitrary byte string (e.g., "abc\x01")
    # returns DER encoding of OCTETSTRING
    return chr(0x04) + asn1_len(octets) + octets
    pass


def asn1_objectidentifier(oid):
    # oid - list of integers representing OID (e.g., [1,2,840,123123])
    # returns DER encoding of OBJECTIDENTIFIER

    #return chr(0x06) + asn1_len(f_octet + base128_value) + f_octet + base128_value
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
asn1 = asn1_tag_explicit(asn1_sequence(asn1_set(asn1_integer(5) + asn1_tag_explicit(asn1_integer(256), 2)
                                                + asn1_tag_explicit(asn1_integer(62527), 11)
                                               )
                                        + asn1_boolean(True)
                                        + asn1_bitstring("110")
                                        + asn1_octetstring("\x00hohoho")
                                        + asn1_null()
                                        #+ asn1_objectidentifier([1,2,840,123123])
                                        #+ asn1_printablestring("boo.")
                                        #+ asn1_utctime("180301014400Z")
                                        ), 0)

open(sys.argv[1], 'w').write(asn1)