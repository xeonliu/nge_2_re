# 《新世纪福音战士 2 ：被创造的世界》汉化计划

> 本仓库最初 Fork 自 [rezual/nge_2_re](https://github.com/rezual/nge_2_re/)
>
> 参见原项目在`EVA Geeks`上的[帖子](https://forum.evageeks.org/thread/1393/Game-Neon-Genesis-Evangelion-2-Another-Cases/700/)

现在仓库的项目结构如下：
- `src`：
  - `app`：用于将游戏资源文件解析提取进数据库
    - `elf_patch`：用于将`SJIS`文本翻译覆盖到 EBOOT.BIN中（Deprecated）
    - `parser/tools`：来自源仓库的文件解析脚本，进行了部分修改
  - `plugin`：使用`C`语言编写的PSP模块，用于替换`EBOOT.BIN`并对原游戏进行内存修改
  - `scripts`：一些脚本
    - `paratranz`：用于处理`Paratranz`平台上存放的文本
    - `mt`：使用机器翻译处理

本仓库代码按 [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html) 协议开源。

本项目**中文翻译文本**按照[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)开源协议共享。

本仓库日文原文与英文翻译文本版权归原作者所有。

# 项目进度&贡献指南
本仓库的所有文本托管于 [Paratranz](https://paratranz.cn/projects/10882) 平台，翻译贡献指南与进度一并于 Paratranz 发布。

图像文件有待进一步处理。

# 适用镜像
+ [ULJS-00061](http://redump.org/disc/96458/)
+ [ULJS-00064](http://redump.org/disc/101162/)

二者存档通用，均显示为`ULJS00061`

## TODO
+ [x] 使用关系型数据库储存解析后的内容
+ [x] 一键导出待翻译文本
+ [x] 从Paratranz导入翻译文本
+ [x] 引入大模型（如Sakura）进行翻译
+ [ ] 建立待翻译图片仓库
+ [x] 建立完整项目结构，能够一键Patch。
+ [ ] 引入CI/CD，能够
  + [ ] 翻译进度统计
  + [x] 翻译问题报告
  + [ ] 统计`$a``%s`等的使用情况
  + ~~[ ] 使用XDelta自动生成Patch~~
+ [ ] 搭建翻译计划网站
+ [x] 对宣发网站存档。
+ [x] 扩展字库
+ [ ] TEXT的自动导入导出
+ [ ] HGAR的自动导入导出

+ [ ] 对TEXT重新进行机翻，处理特殊符号和全半角字符
+ [x] 修改编码映射，防止`厅`编码包含`%`
+ [ ] 补丁以插件（生成器？）形式发布
+ [ ] 动态修改EBOOT文件（所有EBOOT翻译？）

+ [x] 构建Docker镜像

# 开发

1. 安装`uv`

```
```

2. 配置`PSPDEV`工具链

```
```

## Using Docker
```sh
docker build -t pspdev-dev .
docker run -it --rm -v $(pwd):/app -w /app pspdev-dev
```