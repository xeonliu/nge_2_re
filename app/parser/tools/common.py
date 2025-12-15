#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import os
import sys

from app.utils.map import CUSTOM_ENCODE_MAP

# Check encoding only if stdout is available (not in GUI mode or when redirected)
if sys.stdout and hasattr(sys.stdout, 'encoding') and sys.stdout.encoding:
    if (sys.stdout.encoding.lower().strip().replace('-', '').replace(' ', '') != 'utf8'):
        print("Your system\'s default terminal/screen encoding is not UTF-8.\n"
              "Please rerun this script by first setting\n"
              "PYTHONIOENCODING to utf-8.\n"
              "On Windows:\n"
              "set PYTHONIOENCODING=utf-8\n"
              "On Unix:\n"
              "export PYTHONIOENCODING=utf-8")
        sys.exit(-1)

# Common helper functions
def read_uint8(file_handle):
    return ord(file_handle.read(1))

def read_uint16(file_handle):
    return struct.unpack('H', file_handle.read(2))[0]

def read_uint32(file_handle):
    return struct.unpack('I', file_handle.read(4))[0]

def write_uint8(file_handle, value):
    return file_handle.write(struct.pack('B', value))

def write_uint16(file_handle, value):
    return file_handle.write(struct.pack('H', value))

def write_uint32(file_handle, value):
    return file_handle.write(struct.pack('I', value))

def calculate_word_aligned_length(unaligned_length):
    return 4 * int((unaligned_length + 3) / 4)

def get_file_size(file_handle):
    return os.fstat(file_handle.fileno()).st_size
    
def align_size(unaligned_size, alignment):
    return alignment * int((unaligned_size + alignment - 1) / alignment)

def zero_pad_and_align_string(content):
    # Pad string to a size divisible by 4
    padded_length = 4 * int((len(content) + 4) / 4)
    return (content + b'\0\0\0\0')[0:padded_length]

def from_eva_sjis(content):
    # Convert nge2 SJIS to unicode
    try:
        content = content.decode('shift_jis')

    except UnicodeDecodeError:
        raise Exception('There seems to be a character that cannot be converted to unicode. Check the text:' + repr(content))

    # Convert special NGE2 characters
    #content = content.replace('Θ', 'J.')
    #content = content.replace('Α', 'A.')
    #content = content.replace('Τ', 'T.')
    #content = content.replace('Ν', 'N²')
    #content = content.replace('Σ', 'S²')
    #content = content.replace('Ｓ', 'S')

    return content

def to_eva_sjis(content):
    # Convert special NGE2 characters
    # We let most remain as regular ASCII
    #content = content.replace('N²', 'Ν')
    #content = content.replace('S²', 'Σ')
    # Convert unicode to nge2 SJIS
    result = bytearray()
    for char in content:
        # # FIXME:
        # # 1. '-' 转换为 'ー'
        # if char == '—':
        #     char = 'ー'
        # 首先尝试将字符编码为 Shift_JIS
        encoded_char = None
        try:
            encoded_char = char.encode('shift_jis')
        except UnicodeEncodeError:
            # 然后尝试将字符编码为 GB2312（修改后）
            # Find the Entry in which its 'char' equals to char in CUSTOM_ENCODE_MAP
            for entry in CUSTOM_ENCODE_MAP:
                if entry['char'] == char:
                    # If found, use the custom code
                    encoded_char = bytes.fromhex(entry['custom_code'][2:])
                    break
            if encoded_char is None:
                # FIXME: If no custom code is found, fallback to a placeholder character
                encoded_char = '?'.encode('shift_jis')  # Fallback to a placeholder character
                # raise Exception(f'There seems to be a character that cannot be converted to Shift_JIS or GB2312. Check the text: {char}')
        result.extend(encoded_char)
    return bytes(result)

def unique_color(index, total):
    if index == -1:
        return (0, 0, 0)

    if total == 0:
        return (255, 255, 255)

    fractional = index/float(total)
    sectofractional = 6 * fractional
    sectointeger = int(sectofractional)
    sectoremainder = sectofractional - sectointeger
    subsectofractional = min(int(sectoremainder * 256), 255)
    subremaindersectofractional = min(int((1 - sectoremainder) * 256), 255)

    if sectointeger == 0:
        return (255, subsectofractional, 0)

    if sectointeger == 1:
        return (subremaindersectofractional, 255, 0)

    if sectointeger == 2:
        return (0, 255, subsectofractional)

    if sectointeger == 3:
        return (0, subremaindersectofractional, 255)

    if sectointeger == 4:
        return (subsectofractional, 0, 255)

    return (255, 0, subremaindersectofractional)

   