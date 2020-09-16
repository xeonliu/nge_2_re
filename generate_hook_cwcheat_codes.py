#!/usr/bin/env python3

# This script takes in the ./patches/eboot_[ro]data.py files
# and generates CWCheat format codes.
#
#   The cheat codes generated by this script create hooks
#   that hijack the memmove, strlen, and other functions.
#
#   They instead call a look up table translation function
#   that takes a target string address and overwrites the
#   a0/a1/a2 register with the translated string's address
#   if it detects an address that has a translated pair
#
# Tested in PPSSPP emulator only, 
# on hardware might run out of memory,
# crash, or not work
#
# Important information for PPSSPP emulator usage:
#
#     Script output must be stored in:
#       [PPSSPP Memory stick folder]\PSP\Cheats\ULJS00064.ini
#
#     PPSSPP emulator's Dynarec core doesn't play nice when cheats
#     change lib-C functions since the emulator runs HLE variants of these
#
#     To fix this, you need to change the PPSSPP core to Interpreter under:
#          Settings -> Tools -> Developer Tools -> CPU Core -> Interpreter 
#          (NOT the IR Interpreter, use the regular Interpreter!)
#
#     if you don't do this, expect weird bugs! 
#     (It should be noted that breakpoints don't work in the Interpreter core
#      for those considering using PPSSPP's debugger)
#     
#     You also need to disable Fast Memory in PPSSPP under:
#         System -> Fast Memory
#
# Notes: 
# - Some things are still untranslated because the game does direct string 
#   operations (lbu & lb)
#   Cases:
#     [Todo] Patch 088AFBC8: This function is tricky, it seems to be 
#     only used for departing one's home (Misato's).
#     It uses registers to copy the exact 14 bytes or
#     so to the output buffer
# - Some menus crash or cause corruption because the game
#   doesn't know what to do with the longer text
#

import binascii
import os
import json

import tools.common as common

title = 'Shinseiki Evangelion 2: Tsukurareshi Sekai - Another Cases'
serial_number = 'ULJS-00064' 

# The start and stop of the rodata and data sections
GAME_DATA_BASE = 0x89B4640
GAME_DATA_TOP = 0x8A57DFC

# The game doesn't use these memory regions,
# but it might turn out it does in which case it might crash
# ORIGINAL_TOP = 0x9F53900 
FREE_MEM_BASE = 0x09F60000 + 0x00001000
FREE_MEM_TOP =  0x09F97400

# Translation needs about 0x17390 bytes or 92 Kb

# Load the eboot translations
with open ("./translations/eboot.json", "r", encoding='utf-8') as f:
    eboot_translations = json.loads(f.read())

with open ("./translations/global_translation_phrases.json", "r", encoding='utf-8') as f:
    global_translations = json.loads(f.read())

# The translations can have top-level groups,
# collapse the groups into one top-level
eboot_translations_bubbled_up = []
for _, translation_list in eboot_translations.items():
    eboot_translations_bubbled_up.extend(translation_list)

eboot_translations = eboot_translations_bubbled_up

# Generate address, value pairs
cwcheat_code_list = []

def cwcheat(address, value):
    cwcheat_formatted_address = '0x2' + format(address - 0x08800000, '07x').upper()
    cwcheat_formatted_value = '0x' + format(value, '08x').upper()

    cwcheat_code_list.append((cwcheat_formatted_address, cwcheat_formatted_value))

# The buffer will store the Japanese string address
# followed by the translated string address
ADDRESS_REMAP_CONTENT = {}

STRING_BUFFER_START_ADDRESS = FREE_MEM_BASE
STRING_BUFFER_ADDRESS = STRING_BUFFER_START_ADDRESS

# Convert the string buffer to CWCheats
for line in eboot_translations:
    # There should be a human provided translation in the eboot json
    translation = line.get("translation") 

    # If not, look for the translation in the global phrases
    if not translation:
        translation = global_translations.get(line.get("original"), {})
        translation = translation.get("machine_deepl") or translation.get("machine_google")

    # Skip untranslated lines
    if translation is None:
        continue

    translation = common.to_eva_sjis(translation)

    # Parse the technical
    elf, ram, technical_size = line.get("technical", "::,:,:").split(",")
    _, elf_section, elf_address = elf.split(":")
    _, ram_address_str = ram.split(":")
    _, original_size = technical_size.split(":")
    original_size = int(original_size, 10)
    ram_address = int(ram_address_str, 0)

    # Generate the Cwcheat code
    value = common.zero_pad_and_align_string(translation)

    # If the string is less than the original,
    # then just overwrite the original
    if len(value) <= original_size:
        fourths_counter = 0
        while fourths_counter < len(value):
            word_value = int.from_bytes(value[fourths_counter:fourths_counter + 4], byteorder='little', signed=False)
        
            cwcheat(ram_address + fourths_counter, word_value)

            fourths_counter += 4

    else:
        # Add the remap entry
        source_address = ram_address
        destination_address = STRING_BUFFER_ADDRESS
        ADDRESS_REMAP_CONTENT[source_address] = destination_address

        fourths_counter = 0
        while fourths_counter < len(value):
            word_value = int.from_bytes(value[fourths_counter:fourths_counter + 4], byteorder='little', signed=False)
        
            cwcheat(STRING_BUFFER_ADDRESS, word_value)

            fourths_counter += 4
            STRING_BUFFER_ADDRESS += 4

# Convert the address remap buffer to CWCheats
ADDRESS_REMAP_SIZE_ADDRESS = STRING_BUFFER_ADDRESS
cwcheat_formatted_address = '0x2' + format(ADDRESS_REMAP_SIZE_ADDRESS - 0x08800000, '07x').upper()
cwcheat_formatted_value = '0x' + format(len(ADDRESS_REMAP_CONTENT), '08x').upper()
cwcheat_code_list.append((cwcheat_formatted_address, cwcheat_formatted_value))

ADDRESS_REMAP_START_ADDRESS = ADDRESS_REMAP_SIZE_ADDRESS + 4
ADDRESS_REMAP_ADDRESS = ADDRESS_REMAP_START_ADDRESS

for source_address in sorted(ADDRESS_REMAP_CONTENT.keys()):
    destination_address = ADDRESS_REMAP_CONTENT.get(source_address)
    cwcheat_formatted_address = '0x2' + format(ADDRESS_REMAP_ADDRESS - 0x08800000, '07x').upper()
    cwcheat_formatted_value = '0x' + format(source_address, '08x').upper()

    cwcheat_code_list.append((cwcheat_formatted_address, cwcheat_formatted_value))

    ADDRESS_REMAP_ADDRESS += 4

    cwcheat_formatted_address = '0x2' + format(ADDRESS_REMAP_ADDRESS - 0x08800000, '07x').upper()
    cwcheat_formatted_value = '0x' + format(destination_address, '08x').upper()

    cwcheat_code_list.append((cwcheat_formatted_address, cwcheat_formatted_value))

    ADDRESS_REMAP_ADDRESS += 4

# Address remap
LOOKUP_START_ADDRESS = ADDRESS_REMAP_ADDRESS
LOOKUP_ADDRESS = LOOKUP_START_ADDRESS

cwcheat(LOOKUP_ADDRESS, 0x27BDFFEC); LOOKUP_ADDRESS +=4 # addiu sp,sp,-0x14
cwcheat(LOOKUP_ADDRESS, 0xAFBF0000); LOOKUP_ADDRESS +=4 # sw ra, 0x0(sp)
cwcheat(LOOKUP_ADDRESS, 0xAFA80004); LOOKUP_ADDRESS +=4 # sw t0, 0x4(sp)
cwcheat(LOOKUP_ADDRESS, 0xAFA90008); LOOKUP_ADDRESS +=4 # sw t1, 0x8(sp)
cwcheat(LOOKUP_ADDRESS, 0xAFAA000C); LOOKUP_ADDRESS +=4 # sw t2, 0xC(sp)
cwcheat(LOOKUP_ADDRESS, 0xAFAB0010); LOOKUP_ADDRESS +=4 # sw t3, 0x10(sp)

cwcheat(LOOKUP_ADDRESS, 0x3C0A0000 | (GAME_DATA_BASE >> 16)); LOOKUP_ADDRESS +=4 # lui t2, GAME_DATA_BASE.hi
cwcheat(LOOKUP_ADDRESS, 0x354A0000 | (GAME_DATA_BASE & 0xFFFF)); LOOKUP_ADDRESS +=4 # ori t2, t2, GAME_DATA_BASE.lo
cwcheat(LOOKUP_ADDRESS, 0x008A582A); LOOKUP_ADDRESS +=4 # slt t3, a0, t2
cwcheat(LOOKUP_ADDRESS, 0x15600013); LOOKUP_ADDRESS +=4 # bne t3, zero, exit_loop

cwcheat(LOOKUP_ADDRESS, 0x3C0A0000 | (GAME_DATA_TOP >> 16)); LOOKUP_ADDRESS +=4 # lui t2, GAME_DATA_TOP.hi
cwcheat(LOOKUP_ADDRESS, 0x354A0000 | (GAME_DATA_TOP & 0xFFFF)); LOOKUP_ADDRESS +=4 # ori t2, t2, GAME_DATA_TOP.lo
cwcheat(LOOKUP_ADDRESS, 0x0144582A); LOOKUP_ADDRESS +=4 # slt t3, t2, a0
cwcheat(LOOKUP_ADDRESS, 0x1560000F); LOOKUP_ADDRESS +=4 # bne t3, zero, exit_loop

cwcheat(LOOKUP_ADDRESS, 0x3C080000 | (ADDRESS_REMAP_SIZE_ADDRESS >> 16)); LOOKUP_ADDRESS +=4 # lui t0, ADDRESS_REMAP_SIZE_ADDRESS.hi
cwcheat(LOOKUP_ADDRESS, 0x35080000 | (ADDRESS_REMAP_SIZE_ADDRESS & 0xFFFF)); LOOKUP_ADDRESS +=4 # ori t0, ADDRESS_REMAP_SIZE_ADDRESS.lo
cwcheat(LOOKUP_ADDRESS, 0x8D080000); LOOKUP_ADDRESS +=4 # lw t0, 0(t0)
cwcheat(LOOKUP_ADDRESS, 0x3C090000 | (ADDRESS_REMAP_START_ADDRESS >> 16)); LOOKUP_ADDRESS +=4 # lui t1, ADDRESS_REMAP_START_ADDRESS.hi
cwcheat(LOOKUP_ADDRESS, 0x35290000 | (ADDRESS_REMAP_START_ADDRESS & 0xFFFF)); LOOKUP_ADDRESS +=4 # ori t1, ADDRESS_REMAP_START_ADDRESS.lo
cwcheat(LOOKUP_ADDRESS, 0x11000009); LOOKUP_ADDRESS +=4 # beq t0, zero, exit_loop (LABEL: loop)
cwcheat(LOOKUP_ADDRESS, 0x25290008); LOOKUP_ADDRESS +=4 # addiu t1, t1, 8
cwcheat(LOOKUP_ADDRESS, 0x8D2AFFF8); LOOKUP_ADDRESS +=4 # lw t2, -0x8(t1)
cwcheat(LOOKUP_ADDRESS, 0x0144582A); LOOKUP_ADDRESS +=4 # slt t3, t2, a0
cwcheat(LOOKUP_ADDRESS, 0x1560FFFB); LOOKUP_ADDRESS +=4 # bne t3, zero, loop
cwcheat(LOOKUP_ADDRESS, 0x2508FFFF); LOOKUP_ADDRESS +=4 # addiu t0, t0, -1
cwcheat(LOOKUP_ADDRESS, 0x008A582A); LOOKUP_ADDRESS +=4 # slt t3, a0, t2
cwcheat(LOOKUP_ADDRESS, 0x15600002); LOOKUP_ADDRESS +=4 # bne t3, zero, exit_loop
cwcheat(LOOKUP_ADDRESS, 0x00000000); LOOKUP_ADDRESS +=4 # nop
cwcheat(LOOKUP_ADDRESS, 0x8D24FFFC); LOOKUP_ADDRESS +=4 # lw a0, -0x4(t1)
cwcheat(LOOKUP_ADDRESS, 0x8FBF0000); LOOKUP_ADDRESS +=4 # lw ra, 0x0(sp) (LABEL: exit_loop)
cwcheat(LOOKUP_ADDRESS, 0x8FA80004); LOOKUP_ADDRESS +=4 # lw t0, 0x4(sp)
cwcheat(LOOKUP_ADDRESS, 0x8FA90008); LOOKUP_ADDRESS +=4 # lw t1, 0x8(sp)
cwcheat(LOOKUP_ADDRESS, 0x8FAA000C); LOOKUP_ADDRESS +=4 # lw t2, 0xC(sp)
cwcheat(LOOKUP_ADDRESS, 0x8FAB0010); LOOKUP_ADDRESS +=4 # lw t3, 0x10(sp)
cwcheat(LOOKUP_ADDRESS, 0x03E00008); LOOKUP_ADDRESS +=4 # jr ra
cwcheat(LOOKUP_ADDRESS, 0x27BD0014); LOOKUP_ADDRESS +=4 # addiu sp,sp,0x14

LOOKUP_ARG1_START_ADDRESS = LOOKUP_ADDRESS
LOOKUP_ARG1_ADDRESS = LOOKUP_ARG1_START_ADDRESS

cwcheat(LOOKUP_ARG1_ADDRESS, 0x27BDFFF8); LOOKUP_ARG1_ADDRESS += 4 # addiu sp,sp,-0x8
cwcheat(LOOKUP_ARG1_ADDRESS, 0xAFBF0000); LOOKUP_ARG1_ADDRESS += 4 # sw ra, 0x0(sp)
cwcheat(LOOKUP_ARG1_ADDRESS, 0xAFA40004); LOOKUP_ARG1_ADDRESS += 4 # sw a0, 0x4(sp)
cwcheat(LOOKUP_ARG1_ADDRESS, 0x0C000000 | ((LOOKUP_START_ADDRESS & 0x0FFFFFFF) >> 2)); LOOKUP_ARG1_ADDRESS += 4 # jal LOOKUP_START_ADDRESS
cwcheat(LOOKUP_ARG1_ADDRESS, 0x00A02021); LOOKUP_ARG1_ADDRESS += 4 # move a0, a1
cwcheat(LOOKUP_ARG1_ADDRESS, 0x00802821); LOOKUP_ARG1_ADDRESS += 4 # move a1, a0
cwcheat(LOOKUP_ARG1_ADDRESS, 0x8FBF0000); LOOKUP_ARG1_ADDRESS += 4 # lw ra, 0x0(sp)
cwcheat(LOOKUP_ARG1_ADDRESS, 0x8FA40004); LOOKUP_ARG1_ADDRESS += 4 # lw a0, 0x4(sp)
cwcheat(LOOKUP_ARG1_ADDRESS, 0x03E00008); LOOKUP_ARG1_ADDRESS += 4 # jr ra
cwcheat(LOOKUP_ARG1_ADDRESS, 0x27BD0008); LOOKUP_ARG1_ADDRESS += 4 # addiu sp,sp,0x8

LOOKUP_ARG2_START_ADDRESS = LOOKUP_ARG1_ADDRESS
LOOKUP_ARG2_ADDRESS = LOOKUP_ARG2_START_ADDRESS

cwcheat(LOOKUP_ARG2_ADDRESS, 0x27BDFFF8); LOOKUP_ARG2_ADDRESS += 4 # addiu sp,sp,-0x8
cwcheat(LOOKUP_ARG2_ADDRESS, 0xAFBF0000); LOOKUP_ARG2_ADDRESS += 4 # sw ra, 0x0(sp)
cwcheat(LOOKUP_ARG2_ADDRESS, 0xAFA40004); LOOKUP_ARG2_ADDRESS += 4 # sw a0, 0x4(sp)
cwcheat(LOOKUP_ARG2_ADDRESS, 0x0C000000 | ((LOOKUP_START_ADDRESS & 0x0FFFFFFF) >> 2)); LOOKUP_ARG2_ADDRESS += 4 # jal LOOKUP_START_ADDRESS
cwcheat(LOOKUP_ARG2_ADDRESS, 0x00C02021); LOOKUP_ARG2_ADDRESS += 4 # move a0, a2
cwcheat(LOOKUP_ARG2_ADDRESS, 0x00803021); LOOKUP_ARG2_ADDRESS += 4 # move a2, a0
cwcheat(LOOKUP_ARG2_ADDRESS, 0x8FBF0000); LOOKUP_ARG2_ADDRESS += 4 # lw ra, 0x0(sp)
cwcheat(LOOKUP_ARG2_ADDRESS, 0x8FA40004); LOOKUP_ARG2_ADDRESS += 4 # lw a0, 0x4(sp)
cwcheat(LOOKUP_ARG2_ADDRESS, 0x03E00008); LOOKUP_ARG2_ADDRESS += 4 # jr ra
cwcheat(LOOKUP_ARG2_ADDRESS, 0x27BD0008); LOOKUP_ARG2_ADDRESS += 4 # addiu sp,sp,0x8

# Strlen
NEW_STRLEN_START_ADDRESS = LOOKUP_ARG2_ADDRESS
NEW_STRLEN_ADDRESS = NEW_STRLEN_START_ADDRESS

cwcheat(NEW_STRLEN_ADDRESS, 0x27BDFFFC); NEW_STRLEN_ADDRESS += 4 # addiu sp,sp,-0x4
cwcheat(NEW_STRLEN_ADDRESS, 0xAFBF0000); NEW_STRLEN_ADDRESS += 4 # sw ra, 0x0(sp)
cwcheat(NEW_STRLEN_ADDRESS, 0x0C000000 | ((LOOKUP_START_ADDRESS & 0x0FFFFFFF) >> 2)); NEW_STRLEN_ADDRESS += 4 # jal LOOKUP_START_ADDRESS
cwcheat(NEW_STRLEN_ADDRESS, 0x00000000); NEW_STRLEN_ADDRESS += 4 # nop
cwcheat(NEW_STRLEN_ADDRESS, 0x24820001); NEW_STRLEN_ADDRESS += 4 # addiu v0, a0, 0x1 # (overwritten)
cwcheat(NEW_STRLEN_ADDRESS, 0x90830000); NEW_STRLEN_ADDRESS += 4 # lbu v1,0x0(a0) (LABEL: read_byte) # (overwritten)
cwcheat(NEW_STRLEN_ADDRESS, 0x1460FFFE); NEW_STRLEN_ADDRESS += 4 # bne v1, zero, read_byte # (overwritten)
cwcheat(NEW_STRLEN_ADDRESS, 0x24840001); NEW_STRLEN_ADDRESS += 4 # addiu a0, a0, 0x1 # (overwritten)
cwcheat(NEW_STRLEN_ADDRESS, 0x8FBF0000); NEW_STRLEN_ADDRESS += 4 # lw ra, 0x0(sp)
cwcheat(NEW_STRLEN_ADDRESS, 0x27BD0004); NEW_STRLEN_ADDRESS += 4 # addiu sp,sp,0x4
cwcheat(NEW_STRLEN_ADDRESS, 0x03E00008); NEW_STRLEN_ADDRESS += 4 # jr ra # (overwritten)
cwcheat(NEW_STRLEN_ADDRESS, 0x00821023); NEW_STRLEN_ADDRESS += 4 # subu v0,a0,v0 # (overwritten)

cwcheat(0x089A63D8, 0x08000000 | ((NEW_STRLEN_START_ADDRESS & 0x0FFFFFFF) >> 2)); NEW_STRLEN_ADDRESS += 4 # strlen: j NEW_STRLEN_START_ADDRESS
cwcheat(0x089A63DC, 0x00000000); NEW_STRLEN_ADDRESS += 4 # nop

# Memmove
NEW_MEMMOVE_START_ADDRESS = NEW_STRLEN_ADDRESS
NEW_MEMMOVE_ADDRESS = NEW_MEMMOVE_START_ADDRESS

cwcheat(NEW_MEMMOVE_ADDRESS, 0x27BDFFFC); NEW_MEMMOVE_ADDRESS += 4 # addiu sp,sp,-0x4
cwcheat(NEW_MEMMOVE_ADDRESS, 0xAFBF0000); NEW_MEMMOVE_ADDRESS += 4 # sw ra, 0x0(sp)
cwcheat(NEW_MEMMOVE_ADDRESS, 0x0C000000 | ((LOOKUP_ARG1_START_ADDRESS & 0x0FFFFFFF) >> 2)); NEW_MEMMOVE_ADDRESS += 4 # memmove: jal LOOKUP_ARG1_START_ADDRESS
cwcheat(NEW_MEMMOVE_ADDRESS, 0x00000000); NEW_MEMMOVE_ADDRESS += 4 # nop
cwcheat(NEW_MEMMOVE_ADDRESS, 0x8FBF0000); NEW_MEMMOVE_ADDRESS += 4 # lw ra, 0x0(sp)
cwcheat(NEW_MEMMOVE_ADDRESS, 0x27BD0004); NEW_MEMMOVE_ADDRESS += 4 # addiu sp,sp,0x4
cwcheat(NEW_MEMMOVE_ADDRESS, 0x0A26B67B); NEW_MEMMOVE_ADDRESS += 4 # j 0x089AD9EC
cwcheat(NEW_MEMMOVE_ADDRESS, 0x00000000); NEW_MEMMOVE_ADDRESS += 4 # nop

cwcheat(0x089AD9EC, 0x00A4102B) # sltu v0,a1,a0
cwcheat(0x089AD9F0, 0x1040005E) # beq v0,zero,pos_089ADB6C
cwcheat(0x089AD9F4, 0x00805021) # move t2,a0
cwcheat(0x089AD9F8, 0x0A26B683) # j pos_089ADA0C
cwcheat(0x089AD9FC, 0x00000000) # nop

cwcheat(0x089ADA00, 0x08000000 | ((NEW_MEMMOVE_START_ADDRESS & 0x0FFFFFFF) >> 2)) # memmove: j NEW_MEMMOVE_START_ADDRESS
cwcheat(0x089ADA04, 0x00000000) # nop
cwcheat(0x089ADA08, 0x00000000) # nop

# Custom functions that handle strings
NEW_STRCPY_START_ADDRESS = NEW_MEMMOVE_ADDRESS
NEW_STRCPY_ADDRESS = NEW_STRCPY_START_ADDRESS

cwcheat(NEW_STRCPY_ADDRESS, 0x27BDFFFC); NEW_STRCPY_ADDRESS += 4 # addiu sp,sp,-0x4
cwcheat(NEW_STRCPY_ADDRESS, 0xAFBF0000); NEW_STRCPY_ADDRESS += 4 # sw ra, 0x0(sp)
cwcheat(NEW_STRCPY_ADDRESS, 0x0C000000 | ((LOOKUP_ARG1_START_ADDRESS & 0x0FFFFFFF) >> 2)); NEW_STRCPY_ADDRESS += 4 # memmove: jal LOOKUP_ARG1_START_ADDRESS
cwcheat(NEW_STRCPY_ADDRESS, 0x00000000); NEW_STRCPY_ADDRESS += 4 # nop
cwcheat(NEW_STRCPY_ADDRESS, 0x8FBF0000); NEW_STRCPY_ADDRESS += 4 # lw ra, 0x0(sp)
cwcheat(NEW_STRCPY_ADDRESS, 0x27BD0004); NEW_STRCPY_ADDRESS += 4 # addiu sp,sp,0x4
cwcheat(NEW_STRCPY_ADDRESS, 0x00A41025); NEW_STRCPY_ADDRESS += 4 # or v0, a1, a0 # overwritten
cwcheat(NEW_STRCPY_ADDRESS, 0x30420003); NEW_STRCPY_ADDRESS += 4 # andi v0,v0,0x3 # overwritten
cwcheat(NEW_STRCPY_ADDRESS, 0x0A2698D2); NEW_STRCPY_ADDRESS += 4 # j 0x089A6348
cwcheat(NEW_STRCPY_ADDRESS, 0x00000000); NEW_STRCPY_ADDRESS += 4 # nop

cwcheat(0x089A6340, 0x08000000 | ((NEW_STRCPY_START_ADDRESS & 0x0FFFFFFF) >> 2)) # strcpy: j NEW_STRCPY_START_ADDRESS
cwcheat(0x089A6344, 0x00000000) # nop

# Custom functions that handle strings
NEW_089A7AA8_START_ADDRESS = NEW_STRCPY_ADDRESS
NEW_089A7AA8_ADDRESS = NEW_089A7AA8_START_ADDRESS

cwcheat(NEW_089A7AA8_ADDRESS, 0x27BDFFFC); NEW_089A7AA8_ADDRESS += 4 # addiu sp,sp,-0x4
cwcheat(NEW_089A7AA8_ADDRESS, 0xAFBF0000); NEW_089A7AA8_ADDRESS += 4 # sw ra, 0x0(sp)
cwcheat(NEW_089A7AA8_ADDRESS, 0x0C000000 | ((LOOKUP_ARG2_START_ADDRESS & 0x0FFFFFFF) >> 2)); NEW_089A7AA8_ADDRESS += 4 # memmove: jal LOOKUP_ARG2_START_ADDRESS
cwcheat(NEW_089A7AA8_ADDRESS, 0x00000000); NEW_089A7AA8_ADDRESS += 4 # nop
cwcheat(NEW_089A7AA8_ADDRESS, 0x8FBF0000); NEW_089A7AA8_ADDRESS += 4 # lw ra, 0x0(sp)
cwcheat(NEW_089A7AA8_ADDRESS, 0x27BD0004); NEW_089A7AA8_ADDRESS += 4 # addiu sp,sp,0x4
cwcheat(NEW_089A7AA8_ADDRESS, 0x27BDFD70); NEW_089A7AA8_ADDRESS += 4 # addiu sp, sp, -0x290 # overwritten
cwcheat(NEW_089A7AA8_ADDRESS, 0xAFB00260); NEW_089A7AA8_ADDRESS += 4 # sw s0, 0x260(sp) # overwritten
cwcheat(NEW_089A7AA8_ADDRESS, 0x0A269EAC); NEW_089A7AA8_ADDRESS += 4 # j 0x089A7AB0
cwcheat(NEW_089A7AA8_ADDRESS, 0x00000000); NEW_089A7AA8_ADDRESS += 4 # nop

cwcheat(0x089A7AA8, 0x08000000 | ((NEW_089A7AA8_START_ADDRESS & 0x0FFFFFFF) >> 2)) # memmove: j NEW_089A7AA8_START_ADDRESS
cwcheat(0x089A7AAC, 0x00000000) # nop

# Custom functions that handle strings
NEW_088742DC_START_ADDRESS = NEW_089A7AA8_ADDRESS
NEW_088742DC_ADDRESS = NEW_088742DC_START_ADDRESS

cwcheat(NEW_088742DC_ADDRESS, 0x27BDFFFC); NEW_088742DC_ADDRESS += 4 # addiu sp,sp,-0x4
cwcheat(NEW_088742DC_ADDRESS, 0xAFBF0000); NEW_088742DC_ADDRESS += 4 # sw ra, 0x0(sp)
cwcheat(NEW_088742DC_ADDRESS, 0x0C000000 | ((LOOKUP_ARG1_START_ADDRESS & 0x0FFFFFFF) >> 2)); NEW_088742DC_ADDRESS += 4 # memmove: jal LOOKUP_ARG1_START_ADDRESS
cwcheat(NEW_088742DC_ADDRESS, 0x00000000); NEW_088742DC_ADDRESS += 4 # nop
cwcheat(NEW_088742DC_ADDRESS, 0x8FBF0000); NEW_088742DC_ADDRESS += 4 # lw ra, 0x0(sp)
cwcheat(NEW_088742DC_ADDRESS, 0x27BD0004); NEW_088742DC_ADDRESS += 4 # addiu sp,sp,0x4
cwcheat(NEW_088742DC_ADDRESS, 0x27BDFFD0); NEW_088742DC_ADDRESS += 4 # addiu sp, sp, -0x30 # overwritten
cwcheat(NEW_088742DC_ADDRESS, 0xAFB50024); NEW_088742DC_ADDRESS += 4 # sw s5,0x24(sp) # overwritten
cwcheat(NEW_088742DC_ADDRESS, 0x0A21D0B9); NEW_088742DC_ADDRESS += 4 # j 0x088742E4
cwcheat(NEW_088742DC_ADDRESS, 0x00000000); NEW_088742DC_ADDRESS += 4 # nop

cwcheat(0x088742DC, 0x08000000 | ((NEW_088742DC_START_ADDRESS & 0x0FFFFFFF) >> 2)) # memmove: j NEW_088742DC_START_ADDRESS
cwcheat(0x088742E0, 0x00000000) # nop

# Custom functions that handle strings
NEW_08874D44_START_ADDRESS = NEW_088742DC_ADDRESS
NEW_08874D44_ADDRESS = NEW_08874D44_START_ADDRESS

cwcheat(NEW_08874D44_ADDRESS, 0x27BDFFFC); NEW_08874D44_ADDRESS += 4 # addiu sp,sp,-0x4
cwcheat(NEW_08874D44_ADDRESS, 0xAFBF0000); NEW_08874D44_ADDRESS += 4 # sw ra, 0x0(sp)
cwcheat(NEW_08874D44_ADDRESS, 0x0C000000 | ((LOOKUP_START_ADDRESS & 0x0FFFFFFF) >> 2)); NEW_08874D44_ADDRESS += 4 # memmove: jal LOOKUP_START_ADDRESS
cwcheat(NEW_08874D44_ADDRESS, 0x00000000); NEW_08874D44_ADDRESS += 4 # nop
cwcheat(NEW_08874D44_ADDRESS, 0x8FBF0000); NEW_08874D44_ADDRESS += 4 # lw ra, 0x0(sp)
cwcheat(NEW_08874D44_ADDRESS, 0x27BD0004); NEW_08874D44_ADDRESS += 4 # addiu sp,sp,0x4
cwcheat(NEW_08874D44_ADDRESS, 0x27BDFFF0); NEW_08874D44_ADDRESS += 4 # addiu sp, sp, -0x10 # overwritten
cwcheat(NEW_08874D44_ADDRESS, 0xAFB10004); NEW_08874D44_ADDRESS += 4 # sw s1,0x4(sp) # overwritten
cwcheat(NEW_08874D44_ADDRESS, 0x0A21D353); NEW_08874D44_ADDRESS += 4 # j 0x08874D4C
cwcheat(NEW_08874D44_ADDRESS, 0x00000000); NEW_08874D44_ADDRESS += 4 # nop

cwcheat(0x08874D44, 0x08000000 | ((NEW_08874D44_START_ADDRESS & 0x0FFFFFFF) >> 2)) # memmove: j NEW_08874D44_START_ADDRESS
cwcheat(0x08874D48, 0x00000000) # nop

# Bump horizontal slice looking menu character limit from 24 characters to 35
cwcheat(0x08979D9C, 0x28430024) #: slti v1,v0,0x24
cwcheat(0x08979DB4, 0x34050023) # li a1,0x23
cwcheat(0x08979DBC, 0xA0800023) # sb zero,0x23(a0)

# Half-width patch
NEW_HALFWIDTH_START_ADDRESS = NEW_08874D44_ADDRESS
NEW_HALFWIDTH_ADDRESS = NEW_HALFWIDTH_START_ADDRESS

cwcheat(NEW_HALFWIDTH_ADDRESS, 0x026B5021); NEW_HALFWIDTH_ADDRESS += 4 # addu t2,s3,t3 # overwritten
cwcheat(NEW_HALFWIDTH_ADDRESS, 0x000A9843); NEW_HALFWIDTH_ADDRESS += 4 # sra s3,t2,0x1 # overwritten

cwcheat(NEW_HALFWIDTH_ADDRESS, 0x2E460080); NEW_HALFWIDTH_ADDRESS += 4 # sltiu a2,s2,0x80
cwcheat(NEW_HALFWIDTH_ADDRESS, 0x1240000D); NEW_HALFWIDTH_ADDRESS += 4 # beq s2, zero, EIGHT

cwcheat(NEW_HALFWIDTH_ADDRESS, 0x34060069); NEW_HALFWIDTH_ADDRESS += 4 # li a2, 0x69 # i
cwcheat(NEW_HALFWIDTH_ADDRESS, 0x12460009); NEW_HALFWIDTH_ADDRESS += 4 # beq s2, a2, FOUR
cwcheat(NEW_HALFWIDTH_ADDRESS, 0x3406006A); NEW_HALFWIDTH_ADDRESS += 4 # li a2, 0x6A # j
cwcheat(NEW_HALFWIDTH_ADDRESS, 0x12460007); NEW_HALFWIDTH_ADDRESS += 4 # beq s2, a2, FOUR
cwcheat(NEW_HALFWIDTH_ADDRESS, 0x3406006C); NEW_HALFWIDTH_ADDRESS += 4 # li a2, 0x6C # l
cwcheat(NEW_HALFWIDTH_ADDRESS, 0x12460005); NEW_HALFWIDTH_ADDRESS += 4 # beq s2, a2, FOUR
cwcheat(NEW_HALFWIDTH_ADDRESS, 0x34060072); NEW_HALFWIDTH_ADDRESS += 4 # li a2, 0x72 # r
cwcheat(NEW_HALFWIDTH_ADDRESS, 0x12460003); NEW_HALFWIDTH_ADDRESS += 4 # beq s2, a2, FOUR
cwcheat(NEW_HALFWIDTH_ADDRESS, 0x34060027); NEW_HALFWIDTH_ADDRESS += 4 # li a2, 0x27 # '
cwcheat(NEW_HALFWIDTH_ADDRESS, 0x12460001); NEW_HALFWIDTH_ADDRESS += 4 # beq s2, a2, FOUR
cwcheat(NEW_HALFWIDTH_ADDRESS, 0x00000000); NEW_HALFWIDTH_ADDRESS += 4 # nop

cwcheat(NEW_HALFWIDTH_ADDRESS, 0x10000001); NEW_HALFWIDTH_ADDRESS += 4 # b DONE (LABEL: FOUR)
cwcheat(NEW_HALFWIDTH_ADDRESS, 0x34130004); NEW_HALFWIDTH_ADDRESS += 4 # li s3, 0x04

cwcheat(NEW_HALFWIDTH_ADDRESS, 0x34130008); NEW_HALFWIDTH_ADDRESS += 4 # li s3, 0x08 (LABEL: EIGHT)

cwcheat(NEW_HALFWIDTH_ADDRESS, 0x0A21CFE8); NEW_HALFWIDTH_ADDRESS += 4 # j 0x08873F9C # (LABEL: DONE)
cwcheat(NEW_HALFWIDTH_ADDRESS, 0x00000000); NEW_HALFWIDTH_ADDRESS += 4 # nop

cwcheat(0x08873F98, 0x08000000 | ((NEW_HALFWIDTH_START_ADDRESS & 0x0FFFFFFF) >> 2)) # j NEW_HALFWIDTH_START_ADDRESS
cwcheat(0x08873F9C, 0x00000000) # nop

# Cwcheat has a limit of how many lines per cheat, so bucket them
print('_S ' + serial_number)
print('_G ' + title)

print('''
_C0 Debug menu: Daily Special Debug
_L 0x201C97CC 0x088984C0
''')

print('''
_C1 Pulse autowin
This disables player input in the Pulse mini-game
which is needed to prevent a crash from player input
interferring and then changes the Miss check to go
to a Win check
_L 0x2005B478 0x00000000
_L 0x2005B5FC 0x00000000
_L 0x2005B5CC 0x0A216D82
_L 0x2005B5C4 0x00000000
''')

cheat_group = 1
cheat_number = 0
for (address, value) in cwcheat_code_list:

    if cheat_number == 0:
        print('_C1 Translate %s' % cheat_group)

    print('_L ' + address + ' ' + value)

    cheat_number += 1
    if cheat_number >= 30:
        cheat_number = 0
        cheat_group += 1
