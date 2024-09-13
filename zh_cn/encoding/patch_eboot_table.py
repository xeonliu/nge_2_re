"""
Patch the ELF with the modified UTF-16 table.
"""

import rzpipe

eboot_file = "../../eboot/EBOOT.BIN"
tbl_hex_file = "./new_table_bin.txt"
# Start address of Table
table_vm_addr = "0x22bb60"

with rzpipe.open(eboot_file, flags=["-w"]) as rz:
    print(rz.cmd(f"s {table_vm_addr}"))
    print(rz.cmd(f"px 10"))
    print(rz.cmd(f"wxf {tbl_hex_file}"))
    print(rz.cmd(f"px 10"))
    
