import rzpipe
import binascii
import json
import subprocess
eboot_translation_json = "../translations/eboot.json"
eboot_file = "../game_app/EBOOT.BIN"

# extract the technical data from a string
def extract_technical(technical) -> tuple[str,str,str]:
    # elf:data:0x0025089C,ram:0x08A5489C,size:24
    parts = technical.split(",")
    elf_data = parts[0].split(":")[2]
    ram_data = parts[1].split(":")[1]
    size = parts[2].split(":")[1]

    # print("elf_data:", elf_data)
    # print("ram_data:", ram_data)
    # print("size:", size)
    return (elf_data, ram_data, size)

# technical = "elf:data:0x0025089C,ram:0x08A5489C,size:24"
# extract_technical(technical)      

def match_translation(translation : dict[str, str]):
    elf_vmaddr,_,size_str = extract_technical(translation["technical"])
    size: int = int(size_str)
    original = translation["original"]
    trans = translation["translation"]
    return (elf_vmaddr, size, original, trans)

    """Generate JIS Hex String
    """
# def utf8_to_jis(u8_str: str):
#     # # Start echo process
#     # echo_process = subprocess.Popen(["echo", "-n", u8_str], stdout=subprocess.PIPE)
#     # # Start uconv process
#     # uconv_process = subprocess.Popen(["uconv", "-f", "utf-8", "-t", "shift_jis"], stdin=echo_process.stdout, stdout=subprocess.PIPE)
#     # # Start xxd process
#     shift_jis_bytes = u8_str.encode('shift_jis',errors='ignore')
#     xxd_process = subprocess.Popen(["xxd", "-p"], stdin=uconv_process.stdout, stdout=subprocess.PIPE)

#     # Get output from xxd process
#     xxd_output, _ = xxd_process.communicate()

#     # Convert output to string and remove trailing newline
#     hex_string = xxd_output.decode('utf-8').rstrip('\n')

#     return hex_string

def utf8_to_jis(u8_str: str):
    # Encode string to Shift_JIS bytes
    shift_jis_bytes = u8_str.encode('shift_jis')
    # Convert bytes to hex
    hex_string = binascii.hexlify(shift_jis_bytes).decode('utf-8')

    return hex_string
    """
    """

# def write_to_rizin(vmaddr:str, size:int, hex_str:str, filename:str):
#     with rzpipe.open(filename,flags=["-w"]) as rz:
#         if(len(hex_str)<size*2):
#             hex_str = hex_str.ljust(size*2,'0')
#             print(hex_str)
#         # else:
#             # assert(False)
#         print(f'wx {hex_str} @ {vmaddr}')
#         rz.cmd(f'wx {hex_str} @ {vmaddr}')
        

if __name__== '__main__':
    total = 0
    miss = 0
    hit = 0
    with open(eboot_translation_json, 'r') as f:
        eboot_translation_json = json.load(f)
        unsorted_translations: list[dict] = eboot_translation_json["unsorted"]
        # print(unsorted_translations)
        with rzpipe.open(eboot_file,flags=["-w"]) as rz:
            for elem in unsorted_translations:
                vmaddr, size, orig , trans = match_translation(elem)
                total+=1
                if(trans!=None):
                    # print(utf8_to_jis(orig))
                    hex_str = utf8_to_jis(trans)
                    # write_to_rizin(vmaddr,size,jis_hex_str,eboot_file)                
                    if len(hex_str) < size*2:
                        # hex_str = hex_str.ljust(size*2,'0')
                        hit += 1
                    else:
                        hex_str = hex_str[:size]
                        miss += 1
                    print(hex_str)
                    print(f'wx {hex_str} @ {vmaddr}')
                    rz.cmd(f'wx {hex_str} @ {vmaddr}')
                    
        print(f'total{total}miss{miss}hit{hit}')

    