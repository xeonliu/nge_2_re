# 《新世纪福音战士 2 ：被创造的世界》汉化计划

本仓库 Fork 自 [rezual/nge_2_re](https://github.com/rezual/nge_2_re/)，参见[原项目在`forum.evageeks.org`上的帖子](https://forum.evageeks.org/thread/1393/Game-Neon-Genesis-Evangelion-2-Another-Cases/700/)

本仓库在原项目基础上添加了一些目录，它们是：
- `app`：用于将游戏资源文件解析提取进数据库
- `plugin`：使用`C`语言编写的PSP模块，用于对替换`EBOOT.BIN`并对原游戏进行内存修改
- `paratranz`：用于处理`Paratranz`平台上存放的文本
- `mt`：使用机器翻译处理
- `zh_cn`
  - `elf_patch`：用于将~~码表和~~翻译覆盖到 EBOOT.BIN中
  - ~~`encoding`：用于提取 EBOOT.BIN 内嵌的码表，依据词频生成新的码表，并对码表实施替换~~

本仓库**中文翻译文本**按照[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)开源协议共享。

本仓库日文原文与英文翻译文本版权由原作者所有。

# 项目进度&贡献指南
见 [Paratranz](https://paratranz.cn/projects/10882)


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
+ [ ] 修改编码映射，防止`厅`编码包含`%`
+ [ ] 补丁以插件（生成器？）形式发布
+ [ ] 动态修改EBOOT文件（所有EBOOT翻译？）

尽量避免对原可执行文件的修改，逐步移除`Rizin`

### 下载翻译文本并自动检查

```shell
python -m paratranz.download
python -m paratranz.check
```

### 导入翻译文本到数据库
```shell
python -m app.app --import_translation './downloads/evs_trans.json'
```

### 应用 EBOOT 翻译文本
```shell
python -m zh_cn.elf_patch.patcher -t './downloads/eboot_trans.json' ./BOOT.BIN 
```

### 生成 HGAR 文件
