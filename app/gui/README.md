# NGE2 汉化工具图形界面

这是一个基于 tkinter 的图形用户界面，让不会编程的用户也能方便地使用 NGE2 汉化工具。

## 前置要求

`tkinter` 是 Python 标准库的一部分，通常不需要单独安装。但如果遇到 `ModuleNotFoundError: No module named 'tkinter'` 错误，请根据你的系统安装相应的包：

### Linux (Debian/Ubuntu)
```bash
sudo apt-get install python3-tk
```

### Linux (Fedora/RHEL/CentOS)
```bash
sudo dnf install python3-tkinter
```

### macOS
tkinter 通常已包含在 Python 中。如果遇到问题，可能需要重新安装 Python：
```bash
brew install python-tk
```

### Windows
tkinter 通常已包含在 Python 安装中，无需额外操作。

## 启动方式

### 方式一：直接运行启动脚本

```bash
python run_gui.py
```

### 方式二：使用模块方式运行

```bash
python -m app.gui.main
```

## 功能说明

### 数据库操作
- **初始化数据库**：首次使用前需要初始化数据库

### HAR 文件操作
- **导入 HAR 文件（目录）**：选择包含 `.har` 文件的目录进行导入
- **导出 HAR 文件**：导出已导入的 HAR 文件，可选择按前缀过滤

### EVS 和翻译
- **导出 EVS 原文（JSON）**：导出游戏原文为 JSON 格式，用于翻译平台
- **导入翻译（JSON）**：从翻译平台下载的 JSON 文件导入翻译
- **导出翻译（JSON）**：导出已翻译的内容为 JSON 格式

### 图像操作
- **导出图像（PNG）**：导出游戏中的图像文件为 PNG 格式
- **导入翻译后的图像**：导入翻译后的图像文件

### TEXT 文件操作
- **导入 TEXT 文件**：导入游戏的 TEXT 文件（如 `f2tuto.bin`, `f2info.bin`）
- **导出 TEXT 文件**：导出应用翻译后的 TEXT 文件
- **导出 TEXT 为 JSON**：导出 TEXT 文件为 JSON 格式，用于翻译平台

### BIND 文件操作
- **导入 BIND 文件**：导入游戏的 BIND 文件（如 `imtext.bin`, `btimtext.bin`）
- **导出 BIND 文件**：导出应用翻译后的 BIND 文件
- **导出 BIND 为 JSON**：导出 BIND 文件为 JSON 格式，用于翻译平台

### EBOOT 翻译
- **生成 EBTRANS.BIN**：根据翻译 JSON 文件生成 EBOOT 翻译二进制文件
  - 支持单个 JSON 文件或包含 `chunk_*.json` 的目录
  - 生成的 `EBTRANS.BIN` 文件用于游戏运行时加载翻译文本

## 使用提示

1. **首次使用**：请先点击"初始化数据库"按钮
2. **前缀过滤**：在导出 HAR、EVS、翻译时，可以输入前缀（如 `a`, `cev`）来只导出特定文件，留空表示导出全部
3. **文件名过滤**：在导出 TEXT、BIND 文件时，可以输入特定文件名来只导出该文件，留空表示导出全部
4. **操作日志**：右侧日志区域会显示所有操作的输出信息，方便查看进度和错误信息
5. **生成 EBTRANS.BIN**：
   - 可以选择单个翻译 JSON 文件，或选择包含多个 `chunk_*.json` 文件的目录
   - 程序会自动合并所有 chunk 文件并生成最终的 `EBTRANS.BIN`
   - 生成的 `EBTRANS.BIN` 文件需要放置在 PSP 的 `ms0:/PSP/` 目录或 PPSSPP 的相应目录中

## 打包说明

### 使用 PyInstaller 打包

```bash
# 安装 PyInstaller
pip install pyinstaller

# 打包为单文件可执行程序
pyinstaller --onefile --windowed --name "NGE2汉化工具" run_gui.py

# 打包为目录（包含所有文件）
pyinstaller --windowed --name "NGE2汉化工具" run_gui.py
```

### 使用 cx_Freeze 打包

```bash
# 安装 cx_Freeze
pip install cx_Freeze

# 创建 setup.py（需要配置）
# 然后运行
python setup.py build
```

### 使用 py2app (macOS)

```bash
pip install py2app
py2applet --make-setup run_gui.py
python setup.py py2app
```

## 注意事项

- GUI 程序会自动初始化数据库，如果数据库文件不存在会自动创建
- 所有操作都在后台线程中执行，不会阻塞界面
- 如果操作失败，会弹出错误对话框并在日志中显示详细信息
- 建议在使用前先备份重要数据

