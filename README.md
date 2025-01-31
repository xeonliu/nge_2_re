# 《新世纪福音战士 2 ：被创造的世界》汉化计划

本仓库 Fork 自 [rezual/nge_2_re](https://github.com/rezual/nge_2_re/)，参见[原项目在`forum.evageeks.org`上的帖子](https://forum.evageeks.org/thread/1393/Game-Neon-Genesis-Evangelion-2-Another-Cases/700/)

本仓库在原项目基础上添加了一些目录，它们是：
- `app`：用于将游戏资源文件解析提取进数据库
- `plugin`：使用`C`语言编写的PSP模块，用于对替换`EBOOT.BIN`并对原游戏进行内存修改
- `zh_cn`
  - `crowdin`：用于处理从 Crowdin 平台上传和下载的文本。
  - `elf_patch`：用于将~~码表和~~翻译覆盖到 EBOOT.BIN中
  - ~~`encoding`：用于提取 EBOOT.BIN 内嵌的码表，依据词频生成新的码表，并对码表实施替换~~

本仓库**中文翻译文本**按照[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)开源协议共享。

本仓库日文原文与英文翻译文本版权由原作者所有。

# 项目进度&贡献指南
见 [Paratranz](https://paratranz.cn/projects/10882)

## TODO
+ [x] 使用数据库储存解析后的内容
+ [x] 一键导出待翻译文本
+ [x] 从Paratranz导入翻译文本
+ [ ] 搭建实时翻译客户端
+ [ ] 引入大模型（如Sakura）进行翻译
+ [ ] 建立待翻译图片仓库
+ [x] 建立完整项目结构，能够一键Patch。
+ [ ] 引入CI/CD，能够自动生成Patch应用
+ [ ] 搭建翻译计划网站
+ [x] 对宣发网站存档。
+ [x] 扩展字库