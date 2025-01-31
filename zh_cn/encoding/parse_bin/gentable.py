def convert_txt_to_bin(txt_filepath, bin_filepath):
    with open(txt_filepath, 'r') as txt_file:
        hex_data = txt_file.read().strip().split()

    bin_data = bytearray()
    for hex_byte in hex_data:
        bin_data.append(int(hex_byte, 16))

    with open(bin_filepath, 'wb') as bin_file:
        bin_file.write(bin_data)

if __name__ == "__main__":
    txt_filepath = 'utf16_table_bin.txt'
    bin_filepath = 'utf16_table_bin.bin'
    convert_txt_to_bin(txt_filepath, bin_filepath)
    print(f"Converted {txt_filepath} to {bin_filepath}")