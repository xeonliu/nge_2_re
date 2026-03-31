# 项目 Agent 指南

本文用于指导代码助手在本仓库中高效、安全地完成开发与修复任务。

## 项目定位

本仓库用于 PSP 游戏《新世纪福音战士 2：被创造的世界》的汉化补丁构建与工具链开发，核心目标是“可复现的一键构建流水线”与“可维护的资源解析/导入/导出能力”。

## 目录速览

- `app/`：主要 Python 代码
  - `app/cli/`：命令行入口（`uv run -m app.cli.main`）
  - `app/gui/`：GUI 入口与工作流（`run_gui.py`）
  - `app/database/`：数据库模型与 DAO
  - `app/parser/`：资源解析（Python 实现）
  - `app/elf_patch/`：生成 EBOOT 翻译二进制等补丁相关逻辑
- `scripts/`：脚本工具（打包、Paratranz、检查、OCR 等）
- `plugin/`：PSP 侧插件（C 语言/汇编，Makefile 构建）
- `cpp/`：部分解析逻辑的 C++ 实现与测试/benchmark
- `docs/`：使用说明与工作流文档
- `Makefile`：完整流水线封装（本项目首选入口）

## 常用命令

### 环境准备（推荐）

- 创建虚拟环境：`uv venv`
- 安装依赖：`uv sync`（或按 CI 做法 `uv pip install --system ...`）

### GUI 启动

- `python3 run_gui.py`

### 一键构建补丁（从 ISO 到 xdelta）

- 将原始镜像放到 `temp/ULJS00064.iso`（以及可选的 `temp/ULJS00061.iso`）
- 运行：`make full_build`

### 翻译下载/导入

- 下载并合并 Paratranz 翻译：`AUTH_KEY=... make download_trans`
- 导入翻译到 DB：`make import_trans`

### 常用 Make 目标

- `make init_db`：初始化/重建数据库
- `make import_all`：导入 HGAR/TEXT/BIND 等资源
- `make export_all`：导出并生成可回填到 ISO 的资源
- `make plugin`：编译 PSP 插件并复制到导出目录
- `make patch_iso`：对指定 `GAME_ID` 生成 patched ISO 与 xdelta
- `make patch_all_ids`：为 `00061` 与 `00064` 都生成补丁

更完整说明见 [USAGE.md](docs/USAGE.md)。

## Dev environment tips

- 优先用 `make help` 查目标列表，再按“任务 → 命令映射”直接运行对应目标，避免手写脚本串流程。
- Python 依赖优先用 `uv` 管理：`uv venv`、`uv sync`、再用 `uv run ...` 执行（避免系统 Python/依赖漂移）。
- SQLite 数据库默认文件为 `example.db`（位于仓库根目录），DB 被占用时优先关闭 GUI/并行脚本再重试。
- 大型生成物/缓存目录不要当作源码改动：`build/`、`build_cpp/`、`temp/`、`logs/`。
- 涉及 PSP 工具链（`plugin/`、`pspdecrypt`）的目标，在容器/CI 环境更稳定；本机缺工具链时优先只跑 Python 侧目标定位问题。

## 任务 → 命令映射

| 任务 | 首选命令 | 关键输入 | 关键输出 |
|---|---|---|---|
| 从 ISO 全量构建补丁 | `make full_build` | `temp/ULJS00064.iso`（可选 `temp/ULJS00061.iso`），可选 `AUTH_KEY` | `build/*.xdelta`、`build/*_patched_*.iso`、`build/metadata.*` |
| 仅下载并合并翻译 | `AUTH_KEY=... make download_trans` | `AUTH_KEY` | `temp/downloads/*` |
| 仅导入翻译到数据库 | `make import_trans` | `temp/downloads/*` | `example.db`（SQLite） |
| 初始化/重建数据库 | `make init_db` | 无 | `example.db`（SQLite） |
| 导入游戏资源到 DB | `make import_all` | `temp/ULJS00064/PSP_GAME/...`（来自 `make extract_iso`） | `example.db`（SQLite） |
| 导入图片资源 | `make import_images` | `resources/trans_pic/trans` | `example.db`（SQLite） |
| 从 DB 导出资源到 build 目录 | `make export_all` | `example.db` | `build/ULJS00064/PSP_GAME/...` |
| 构建 PSP 插件并回填 | `make plugin` | PSPDEV 工具链 | `build/ULJS00064/PSP_GAME/SYSDIR/EBOOT.BIN` |
| 解密 EBOOT（生成 BOOT.BIN） | `make decrypt_eboot` | `temp/ULJS00064/PSP_GAME/SYSDIR/EBOOT.BIN` | `build/ULJS00064/PSP_GAME/SYSDIR/BOOT.BIN` |
| 生成 metadata | `make gen_metadata` | `build/ULJS00064/PSP_GAME/PIC0.PNG` | `build/metadata.json`、`build/metadata.png`、`build/ULJS00064/PSP_GAME/USRDIR/metadata.raw` |
| 仅重打 ISO + xdelta | `make patch_iso GAME_ID=00064` | `temp/ULJS00064.iso`、`build/ULJS00064/...` | `build/ULJS00064_patch_*.xdelta`、`build/ULJS00064_patched_*.iso` |
| 启动 GUI 工具 | `python3 run_gui.py` | Python 依赖 | GUI 窗口 |
| 运行单测 | `uv run -m pytest` | Python 依赖 | 测试报告 |
| 代码风格检查 | `uv run ruff check .` | ruff | 检查报告 |

## 失败恢复流程

- 先定位卡住的阶段：优先单独运行对应目标（如 `make import_trans` / `make export_all`），不要每次都从 `make full_build` 重来。
- 确认关键前置：`temp/ULJS00064.iso` 是否存在、`AUTH_KEY` 是否设置、`uv` 依赖是否安装完成。
- 遇到数据库锁/脏状态（SQLite）：
  - 退出所有占用 DB 的进程（尤其是 GUI 或并行脚本），再重跑目标
  - 仍不行时，删除 `example.db` 后执行 `make init_db`，再按顺序执行 `make import_all` → `make import_trans` → `make export_all`
- 遇到 build 目录内容不一致：
  - 运行 `make clean` 清理 `build/`
  - 只重跑需要的阶段（例如只改了翻译：`make import_trans && make export_all && make patch_all_ids`）
- 遇到第三方工具/插件构建失败：
  - 单独运行 `make plugin` 或 `make decrypt_eboot`，确认 PSPDEV/编译器可用后再回到主流程
- 仍无法恢复时的“安全重置”建议（尽量不动 ISO 与下载翻译）：
  - 删除 `build/`（`make clean`）
  - 删除 `example.db`
  - 从 `make init_db` 起按流水线逐段跑到出问题的那一步

## 修改代码时的优先级与约束

- 优先修改现有实现并沿用仓库内既有模式（CLI/Makefile 工作流优先于自定义脚本）。
- 不要提交或写入任何密钥（如 `AUTH_KEY`、第三方 Token）到代码或文档中。
- 尽量避免改动生成物/缓存目录：`build/`、`build_cpp/`、`temp/`、`logs/`。
- 修改与补丁流水线相关逻辑时，优先保证 `make full_build` 的可复现性与幂等性。

## 修改边界与跨语言一致性

- 二进制格式（HGAR/HGPT/TEXT/BIND/ELF）相关修改优先视为“破坏性变更”，必须同时覆盖：解析、写回、以及至少一个最小回归验证路径。
- Python 与 C++ 的同名格式逻辑必须保持一致：
  - C++：`cpp/parser/include/` 与 `cpp/parser/src/`
  - Python：`app/parser/tools/` 与 `app/database/dao/`
- 涉及结构体字段、对齐、大小端、压缩/校验的修改时：
  - 先确认“文件布局”是否变化（字段顺序、padding、计数单位、offset 基址）
  - 再同步更新两端的读写实现，避免出现“能解析但写回破坏”的情况
- PSP 插件与 EBOOT/ELF 相关修改边界：
  - `plugin/`、`app/elf_patch/` 的改动优先保证在真实 PSP/PPSSPP 上可用；不要随意改动固定地址、导入表、二进制块布局
  - 任何影响文本编码、字库、渲染路径的改动，都需要同时检查：码表、字体资源、以及运行时 hook 的一致性

## 验证与质量门槛（建议每次改动后执行）

- 单测：`uv run -m pytest`
- 代码风格/静态检查：`uv run ruff check .`

如果改动触及 GUI/打包，请至少验证 `python3 run_gui.py` 能正常启动；如果改动触及 Makefile 流水线，请至少验证相关目标能被解析并能运行到关键步骤。

## Testing instructions

- CI 计划在 `.github/workflows/`：核心流水线见 `build.yml`，GUI 打包见 `build-gui.yml`。
- 提交前最小本地检查：
  - `uv run ruff check .`
  - `uv run -m pytest`
- 改动涉及 Makefile/流水线时，至少跑到出问题阶段的对应目标（例如只改翻译导入就跑 `make import_trans`，只改导出逻辑就跑 `make export_all`）。
- 改动涉及 PSP 插件/第三方工具构建时，至少本地或容器内验证 `make plugin` / `make decrypt_eboot` 能跑通。

## 需要了解的上下文

- 工作流依赖 `Makefile` 串联：ISO 解包 → DB 初始化/导入 → 翻译导入 → 资源导出 → 插件构建 → EBOOT 解密/回填 → 生成 metadata → 重新打包 ISO → 生成 xdelta。
- 代码以 Python 为主，但 PSP 插件与部分解析逻辑存在 C/C++ 实现，修改时注意跨语言数据格式的一致性。

## PR instructions

- 标题格式：`[<area>] <Title>`，示例：`[parser] Fix HGPT header parse`、`[gui] Improve workflow logs`
- 合并前至少通过：
  - `uv run ruff check .`
  - `uv run -m pytest`
- 涉及二进制格式/写回路径的改动必须带验证步骤（最少：能导出并写回到 `build/ULJS00064/...`，且后续 `make patch_iso` 不报错）。
