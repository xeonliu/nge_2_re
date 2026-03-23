import struct
import argparse

class SfoEditor:
    def __init__(self, file_path):
        self.file_path = file_path
        with open(file_path, 'rb') as f:
            self.data = bytearray(f.read())
        
        # 解析 Header
        # magic(4), version(4), key_start(4), data_start(4), count(4)
        header = struct.unpack('<4sIIII', self.data[:20])
        self.magic = header[0]
        self.version = header[1]
        self.key_table_start = header[2]
        self.data_table_start = header[3]
        self.count = header[4]
        
        self.entries = []
        self._parse_entries()

    def _parse_entries(self):
        self.entries = []
        for i in range(self.count):
            offset = 20 + (i * 16)
            # key_off(2), data_type(2), data_len(4), data_max_len(4), data_off(4)
            entry = list(struct.unpack('<HHIII', self.data[offset:offset+16]))
            
            # 获取 Key Name
            key_addr = self.key_table_start + entry[0]
            key_name = ""
            while self.data[key_addr] != 0:
                key_name += chr(self.data[key_addr])
                key_addr += 1
            
            self.entries.append({
                'name': key_name,
                'type': entry[1],
                'len': entry[2],
                'max_len': entry[3],
                'data_off': entry[4],
                'index_offset': offset
            })

    def get_value(self, key_name):
        """读取指定键的值"""
        for entry in self.entries:
            if entry['name'] == key_name:
                addr = self.data_table_start + entry['data_off']
                if entry['type'] == 0x0404:  # UInt32
                    return struct.unpack('<I', self.data[addr:addr+4])[0]
                else:  # UTF-8 String
                    return self.data[addr:addr+entry['len']].decode('utf-8').rstrip('\0')
        return None

    def set_value(self, key_name, new_value):
        """修改指定键的值（不改变原始预留长度）"""
        for entry in self.entries:
            if entry['name'] == key_name:
                addr = self.data_table_start + entry['data_off']
                
                if entry['type'] == 0x0404:  # UInt32
                    struct.pack_into('<I', self.data, addr, int(new_value))
                else:  # String
                    encoded = new_value.encode('utf-8') + b'\0'
                    if len(encoded) > entry['max_len']:
                        print(f"警告: 新值过长 ({len(encoded)} > {entry['max_len']})，将被截断")
                        encoded = encoded[:entry['max_len']-1] + b'\0'
                    
                    # 写入数据并更新实际长度
                    self.data[addr:addr+len(encoded)] = encoded
                    struct.pack_into('<I', self.data, entry['index_offset'] + 4, len(encoded))
                return True
        return False

    def save(self, new_path=None):
        """保存文件"""
        target = new_path if new_path else self.file_path
        with open(target, 'wb') as f:
            f.write(self.data)
        print(f"保存成功: {target}")

# --- 使用示例 ---
if __name__ == "__main__":
    args = argparse.ArgumentParser(description="PSP PARAM.SFO Editor")
    args.add_argument("file", help="要编辑的 PARAM.SFO 文件路径")
    args.add_argument("--output", "-o", help="保存修改后的文件路径")
    args = args.parse_args()
    sfo = SfoEditor(args.file)
    
    # 1. 读取并显示所有键值对
    for entry in sfo.entries:
        print(f"Key: {entry['name']}, Type: {entry['type']}, Length: {entry['len']}, Max Length: {entry['max_len']}")
        print(f"Value: {sfo.get_value(entry['name'])}")
        print("-" * 40)
    
    # 2. 修改
    sfo.set_value("TITLE", "新世纪福音战士２ 被创造的世界")
    
    # 3. 保存
    sfo.save(args.output)