# 补丁元数据生成功能

## 概述

每次补丁生成时，系统会自动生成包含以下信息的元数据：

1. **Git 提交信息**
   - 主仓库的 commit hash
   - 所有 submodule 的 commit hash

2. **翻译统计信息** (从 ParaTranz API 获取)
   - 词条总数
   - 已翻译条数及百分比
   - 有疑问条数
   - 已审核条数及百分比
   - 文件大小
   - 生成时间

3. **输出文件**
   - `build/metadata.json` - JSON 格式的元数据
   - `build/metadata.png` - 480x272 分辨率的可视化图片

## 使用方法

### 手动生成元数据

```bash
# 基本用法
make gen_metadata

# 或直接调用脚本
uv run -m scripts.gen_metadata

# 指定输出路径
uv run -m scripts.gen_metadata --output custom/path/metadata.json --image custom/path/metadata.png
```

### 在 CI 中自动生成

元数据会在每次 `make patch_iso` 时自动生成。CI workflow 中会：

1. 自动生成元数据
2. 在 CI 日志中显示 JSON 内容
3. 将 `metadata.json` 和 `metadata.png` 上传为 artifacts

## JSON 格式示例

```json
{
  "generated_at": "2026-02-07T15:24:52.411Z",
  "git": {
    "main_commit": "abc123def456",
    "submodules": {
      "third_party/pgftool": "1234567890ab",
      "third_party/pspdecrypt": "fedcba098765",
      "resources/trans_pic": "abcdef123456"
    }
  },
  "translation": {
    "id": 1500714,
    "createdAt": "2026-02-07T15:24:52.411Z",
    "project": 10882,
    "total": 40466,
    "translated": 40009,
    "disputed": 207,
    "checked": 3496,
    "reviewed": 914,
    "hidden": 0,
    "size": 6170755,
    "duration": 2340
  }
}
```

## 图片格式

生成的 PNG 图片为 480x272 分辨率，包含：

- 标题：NGE2 汉化补丁构建信息
- Git commit 信息（主仓库和子模块）
- 翻译统计（词条数、翻译进度、审核进度等）
- 生成时间戳

## 环境变量

- `AUTH_KEY` - ParaTranz API 认证密钥（可选）
  - 如果不提供，将跳过翻译统计信息的获取
  - 可以通过命令行参数 `--auth-key` 或环境变量提供

## 技术细节

- 脚本位置: `scripts/gen_metadata.py`
- Python 依赖: `requests`, `pillow`
- 默认字体: DejaVu Sans (Linux 系统默认字体)
- 图片格式: PNG, RGB 模式

## 故障排除

### 无法获取翻译统计

如果看到 "Warning: No AUTH_KEY provided, skipping ParaTranz stats"，这是正常的。确保：

1. 在 CI 中，`AUTH_KEY` secret 已配置
2. 在本地使用时，设置 `AUTH_KEY` 环境变量

### 图片生成失败

如果 Pillow 未安装，脚本会跳过图片生成但仍会生成 JSON 文件。安装 Pillow:

```bash
uv pip install pillow
# 或
pip install pillow
```

### 字体显示问题

如果系统没有 DejaVu Sans 字体，脚本会回退到默认字体。可以安装:

```bash
# Ubuntu/Debian
sudo apt-get install fonts-dejavu

# 或使用系统默认字体
```
