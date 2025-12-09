# HGPT 图像翻译工作流程

## 概述

本工作流程支持从 NGE2 游戏中提取、翻译和重新打包 HGPT 格式的图像文件。

## 数据库设计

### 核心表结构

**Hgpt 表** - 存储去重后的 HGPT 图像
- `key`: MD5 hash（主键，用于去重）
- `content`: 原始 HGPT 二进制数据（备份）
- `png_image`: 导出的原始 PNG 图像
- `png_translated`: 翻译后的 PNG 图像（优先使用）
- 元数据字段：`width`, `height`, `pp_format`, `palette_size`, `divisions` 等

**HgarFile 表** - HGAR 中的文件条目
- `hgpt_key`: 外键，指向 Hgpt 表
- `encoded_identifier`: 第 31 位标记是否压缩
- 文件被压缩时存储解压后的数据，导出时重新压缩

### 去重机制

- 同一图像在多个 HAR 文件中出现时，只存储一次
- 通过 MD5 hash 识别重复图像
- 多个 HgarFile 记录可以引用同一个 Hgpt 记录

## 使用流程

### 1. 导入 HAR 文件

```bash
python -m app.cli.main --import_har /path/to/har/files
```

此步骤会：
- 解析所有 `.har` 文件
- 提取 HGPT 图像并去重
- 自动导出为 PNG 存储在数据库
- 处理压缩的 HGPT 文件（`.zpt`）

### 2. 导出图像用于翻译

```bash
python -m app.cli.main --export_images /path/to/output
```

导出结果：
```
/path/to/output/
├── subtitle/
│   ├── day00#id252_a1b2c3d4.png
│   ├── day01#id93_e5f6g7h8.png
│   └── ...
├── menu/
│   └── ...
└── ...
```

文件名格式：`{short_name}_{hash[:8]}.png`
- `short_name`: 文件的简短名称（如 `day00#id252`）
- `hash[:8]`: HGPT 的 MD5 前 8 位（用于匹配）

### 3. 翻译图像

使用任意图像编辑工具（Photoshop, GIMP 等）编辑导出的 PNG 文件。

**注意事项**：
- 必须保持图像尺寸不变
- 必须保持文件名不变（特别是 hash 部分）
- 对于调色板图像，建议保持调色板模式

### 4. 导入翻译后的图像

```bash
python -m app.cli.main --import_images /path/to/translated
```

此步骤会：
- 递归扫描目录中的所有 PNG 文件
- 根据文件名中的 hash 匹配数据库中的图像
- 验证尺寸是否匹配
- 将翻译版本存储到 `png_translated` 字段

### 5. 重新打包 HAR 文件

```bash
python -m app.cli.main --output_hgar /path/to/output
```

此步骤会：
- 重建所有 HGAR 文件
- **自动使用翻译后的图像**（如果存在 `png_translated`）
- 重新压缩需要压缩的文件
- 保持原始文件结构

## 技术细节

### 压缩格式

压缩的 HGPT 文件（`.zpt`）使用自定义格式：
```
[4 bytes: uncompressed size] + [zlib compressed data without header/trailer]
```

- 压缩：`struct.pack('<I', size) + zlib.compress(data)[2:-4]`
- 解压：读取 4 字节大小，然后 `zlib.decompress(data, -15)`

### 重建逻辑

`HgptDao.get_hgpt_data()` 重建 HGPT 时的优先级：
1. 如果存在 `png_translated`，从翻译版本重建
2. 否则，从 `png_image` 重建
3. 如果都没有，使用原始 `content`

### 流式处理

所有 HGPT 解析和生成都使用 `BytesIO`，不创建临时文件：
```python
file_stream = io.BytesIO(hgpt_data)
reader = hgp.HgptReader(file_stream)
```

## API 接口

### HgptDao 方法

```python
# 保存 HGPT（自动去重和导出 PNG）
HgptDao.save(hgpt_data: bytes) -> str

# 获取 HGPT 数据（自动使用翻译版本）
HgptDao.get_hgpt_data(hgpt_key: str) -> bytes

# 导入单个翻译图像
HgptDao.import_translated_png(hgpt_key: str, translated_png_data: bytes)

# 批量导出所有图像
HgptDao.export_all_images(output_dir: str) -> Dict[str, List[Tuple[str, str]]]

# 批量导入翻译图像
HgptDao.import_translated_images(translation_dir: str) -> int
```

## 完整工作流程示例

```bash
# 1. 初始化并导入游戏资源
python -m app.cli.main --import_har /mnt/psp/PSP_GAME/USRDIR

# 2. 导出图像到工作目录
python -m app.cli.main --export_images ./work/images_original

# 3. 翻译图像（手动使用图像编辑软件）
# ... 编辑 ./work/images_original/ 中的 PNG 文件 ...
# ... 保存到 ./work/images_translated/ ...

# 4. 导入翻译后的图像
python -m app.cli.main --import_images ./work/images_translated

# 5. 重新打包游戏资源
python -m app.cli.main --output_hgar ./output/USRDIR

# 6. 复制到 PSP
# cp -r ./output/USRDIR/* /mnt/psp/PSP_GAME/USRDIR/
```

## 故障排除

### 图像尺寸不匹配
```
Error: Size mismatch: expected 256x128, got 256x256
```
- 原因：翻译后的图像尺寸与原始图像不一致
- 解决：调整图像到原始尺寸

### Hash 未找到
```
Skip (not found): xxx_12345678.png (hash: 12345678)
```
- 原因：文件名中的 hash 在数据库中不存在
- 解决：检查文件名是否被修改，或重新导出图像

### 多个匹配项
```
Warning: Multiple matches for 12345678, using first
```
- 原因：hash 前缀太短，匹配到多个图像（极少见）
- 影响：系统会使用第一个匹配项，通常不影响结果

## 注意事项

1. **备份**：导入 HAR 文件会重置数据库，请先备份
2. **尺寸**：翻译图像必须保持原始尺寸
3. **文件名**：导入时依赖文件名中的 hash，不要修改
4. **调色板**：调色板图像转换为 RGBA 可能增加文件大小
5. **压缩**：系统自动处理压缩，无需手动操作
