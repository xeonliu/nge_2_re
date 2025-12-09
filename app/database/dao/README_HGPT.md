# HGPT 数据库设计说明

## 设计理念

参考 `EVSDao` 的设计模式，HGPT 采用**去重存储 + 可修改**方案：
- 使用 MD5 hash 作为唯一键
- 相同的图像只存储一次
- 多个 `HgarFile` 可以引用同一个 `Hgpt`
- **支持图像修改**：PNG 可以被编辑和替换

## 核心改进：支持图像修改

### 为什么需要支持修改？

在游戏本地化/翻译过程中，经常需要：
- 📝 翻译图像中的文字（菜单、标题等）
- 🎨 替换图像资源
- ✏️ 修正图像内容

### 数据存储策略

```python
class Hgpt:
    key: str              # MD5 hash（去重键）
    content: bytes        # 原始 HGPT 数据（备份）
    png_image: bytes      # PNG 格式（可编辑版本）⭐
    # ... 元数据（尺寸、格式等）
```

**关键设计**：
- `content`: 保存原始数据作为备份
- `png_image`: 可以被修改和替换 ⭐
- 重建时使用 `png_image` 而非 `content`

## 技术优化

### 流式读取（无临时文件）
`HgptReader` 支持从文件流（`BytesIO`）直接读取数据，避免创建临时文件：
```python
import io
from app.parser.tools import hgp

# 直接从内存读取
hgpt_data = b'...'  # 解压后的 HGPT 数据
stream = io.BytesIO(hgpt_data)
reader = hgp.HgptReader(stream)
hgpt_image = reader.read()
```

这样做的好处：
- ✅ **性能提升**：避免磁盘 I/O
- ✅ **内存高效**：无需写入临时文件
- ✅ **线程安全**：无需管理临时文件清理
- ✅ **向下兼容**：仍支持文件路径方式

## 数据库结构

```
Hgar (压缩包)
  └── HgarFile (文件条目)
        ├── Hgpt (图像数据，去重)
        ├── EVSEntry (脚本条目)
        └── Raw (其他文件)
```

### 核心表

#### `hgpts` - HGPT 图像数据表
| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | Integer | 主键 |
| `key` | String | MD5 hash（唯一，用于去重） |
| `content` | LargeBinary | 原始 HGPT 数据（用于重建） |
| `png_image` | LargeBinary | PNG 图像（用于预览/翻译） |
| `width` / `height` | Integer | 图像尺寸 |
| `pp_format` | Integer | 像素格式 (0x13/0x14/0x8800) |
| `palette_size` | Integer | 调色板大小（RGBA 为 NULL） |
| `has_extended_header` | Boolean | 扩展头标志 |
| `division_name` | String | 分区名称 |
| `divisions` | JSON | 分区信息 |

#### `hgar_files` - 文件条目表
| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | Integer | 主键 |
| `short_name` / `long_name` | String | 文件名 |
| `hgar_id` | Integer | 所属压缩包 |
| `hgpt_key` | String | 引用的 HGPT（可为空） |
| `file_size` | Integer | 原始大小 |
| `compressed_size` | Integer | 压缩大小 |

## 使用示例

### 1. 保存 HGAR 包（自动处理 HGPT）

```python
from app.database.dao.hgar_file import HGARFileDao
from app.parser.tools import HGArchiveFile

# 解析 HGAR 得到文件列表
hgar_files = [
    HGArchiveFile(short_name=b'scene01.hpt', content=hpt_data1, ...),
    HGArchiveFile(short_name=b'scene02.hpt', content=hpt_data2, ...),
    HGArchiveFile(short_name=b'scene03.hpt', content=hpt_data1, ...),  # 重复图像！
    HGArchiveFile(short_name=b'script.evs', content=evs_data, ...),
]

# 保存到数据库（自动去重）
HGARFileDao.save(hgar_id=1, hgar_files=hgar_files)

# 输出：
#   [HPT] scene01.hpt
#   [HGPT] Saved: abc12345... (800x600)
#   [HPT] scene02.hpt
#   [HGPT] Saved: def67890... (1024x768)
#   [HPT] scene03.hpt
#   [HGPT] Duplicate found: abc12345... (skipping)  # 自动去重！
#   [EVS] script.evs
```

### 2. 重建 HGAR 包

```python
from app.database.dao.hgar_file import HGARFileDao

# 从数据库重建文件列表
hgar_files = HGARFileDao.form(hgar_id=1)

# 输出：
#   Rebuilding: scene01.hpt
#   Rebuilding: scene02.hpt
#   Rebuilding: scene03.hpt  # 使用相同的 hgpt_key，自动复用数据
#   Rebuilding: script.evs

# 打包成 HGAR
for file in hgar_files:
    write_to_archive(file.short_name, file.content)
```

### 3. 完整工作流（解析 → 翻译 → 重建）

```python
# Step 1: 解析并保存
hgar_wrapper = HGARWrapper()
hgar_wrapper.open('/path/to/archive.har')
HGARFileDao.save(hgar_id=1, hgar_files=hgar_wrapper.files)

# Step 2: 翻译工作
# - EVS 文本通过 sentences/translations 表处理
# - HGPT 图像可以导出 PNG 进行翻译

# Step 3: 重建 HGAR
rebuilt_files = HGARFileDao.form(hgar_id=1)
hgar_wrapper.files = rebuilt_files
hgar_wrapper.save('/path/to/translated_archive.har')
```

### 4. 查询和统计

```python
from app.database.entity.hgpt import Hgpt
from app.database.entity.hgar_file import HgarFile
from sqlalchemy import func

# 查找重复使用的图像
duplicates = db.query(
    Hgpt.key,
    Hgpt.width,
    Hgpt.height,
    func.count(HgarFile.id).label('usage_count')
).join(HgarFile).group_by(Hgpt.key).having(
    func.count(HgarFile.id) > 1
).all()

for key, w, h, count in duplicates:
    print(f"图像 {key[:8]}... ({w}x{h}) 被使用了 {count} 次")

# 输出示例：
# 图像 abc12345... (800x600) 被使用了 15 次
# 图像 def67890... (1024x768) 被使用了 8 次
```

## 去重效果

假设有 1000 个 HGAR 文件，其中包含 5000 个图像引用，但实际只有 2000 个不同的图像：

- **无去重**: 存储 5000 个图像副本
- **有去重**: 存储 2000 个唯一图像 + 5000 个引用记录

节省空间约 60%！

## 与 EVS 的对比

| 特性 | EVS | HGPT |
|------|-----|------|
| 去重键 | `Sentence.key` (MD5) | `Hgpt.key` (MD5) |
| 内容存储 | `Sentence.content` (文本) | `Hgpt.content` (二进制) |
| 额外数据 | `Translation` (翻译) | `png_image` (预览) |
| 引用方式 | `EVSEntry.sentence_key` | `HgarFile.hgpt_key` |
| DAO 方法 | `save()` / `form_evs_wrapper()` | `save()` / `get_hgpt_data()` |

两者都遵循相同的设计模式：**内容去重 + 引用关联**。
