import math
import sys 
from itertools import chain

# https://tools.ietf.org/html/rfc4648#section-4
base64_alphabet = dict(
    zip(range(0, 64), [
                          chr(i) for i in chain(range(65, 91),   # A-Z
                                                range(97, 123),  # a-z
                                                range(48, 58),   # 0-9
                                                range(43, 44),   # +
                                                range(47, 48))   # /
    ])
)

base64_alphabet_decode = dict(
    zip([
          chr(i) for i in chain(range(65, 91),   # A-Z
                                range(97, 123),  # a-z
                                range(48, 58),   # 0-9
                                range(43, 44),   # +
                                range(47, 48))   # /
        ], range(0, 64))
)


def chunk(l, chunk_len):
    num_chunks = int(math.ceil(len(l) / chunk_len))
    chunked = []
    curr_chunk_ind = 0
    for _ in range(num_chunks):
        chunked.append(l[slice(curr_chunk_ind, curr_chunk_ind + chunk_len)])
        curr_chunk_ind += chunk_len
    return chunked


def btoa(bytes):
    byte_chunks = chunk(bytes, 3)

    a = []

    last_encoding = []
    terminating_chunk = byte_chunks[-1]
    if len(terminating_chunk) < 3:
        three_byte_chunks = byte_chunks[:-1]

        if len(terminating_chunk) == 1:
            # the last chunk only has 8 bits, pad to 12 bits
            right_padding = '0' * 4 # pad right with 4 bits
        else:
            # the last chunk has 16 bits, pad to 18 bits
            right_padding = '0' * 2 # pad right with 2 bits

        bits = ''.join([ format(byte, '08b') for byte in terminating_chunk ]) + right_padding
        six_bit_groups = chunk(bits, 6)
        for six_bits in six_bit_groups:
            last_encoding.append(base64_alphabet[int(six_bits, 2)])

        # number of padding chars to add
        num_padding_chars = 3 - len(terminating_chunk)
        while num_padding_chars > 0:
            num_padding_chars -= 1
            last_encoding.append('=')
    else:
        three_byte_chunks = byte_chunks

    # read through each 3 byte chunk
    for byte_chunk in three_byte_chunks:
        # format each byte chunk into binary with leading zerso then join them
        i = ''.join([ format(byte, '08b') for byte in byte_chunk ])

        # chunk the 24 bits into 4 6-bit groups
        six_bit_groups = chunk(i, 6)

        # read each 6-bit group
        for six_bits in six_bit_groups:
            a.append(base64_alphabet[int(six_bits, 2)])

    return a + last_encoding


def atob(ascii):
    # chunk the ascii into 24 bit / 4 6-bit segments
    ascii_chunks = chunk(ascii, 4)

    last_ind = len(ascii_chunks) - 1
    # read all the full 24 bit chunks into 3 bytes
    for ind, ascii_chunk in enumerate(ascii_chunks):
        if ind == last_ind and '=' in ascii_chunk:
            # Does the last chunk have one or two padding chars?
            if '=' == ascii_chunk[-1] and '=' == ascii_chunk[-2]:
                bin_str = format(base64_alphabet_decode[ascii_chunk[0]], '06b') + \
                          format(base64_alphabet_decode[ascii_chunk[1]], '06b')
            else:
                bin_str = format(base64_alphabet_decode[ascii_chunk[0]], '06b') + \
                          format(base64_alphabet_decode[ascii_chunk[1]], '06b') + \
                          format(base64_alphabet_decode[ascii_chunk[2]], '06b')
        else:
            bin_str = ''.join([ format(base64_alphabet_decode[enc_char], '06b') for enc_char in ascii_chunk ])
        bin_chunks = chunk(bin_str, 8)
        for byte in bin_chunks:
            yield int(byte, 2).to_bytes(1, sys.byteorder)


if __name__ == '__main__':
    text = b'''Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.'''
    
    a = btoa(text)

    print(''.join(a))
    print(''.join([ b.decode('utf-8') for b in atob(''.join(a)) ]))

