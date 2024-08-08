# 《新世纪福音战士 2 ：被创造的世界》汉化计划

本仓库由 [rezual/nge_2_re](https://github.com/rezual/nge_2_re/) Fork 而来，原项目的工作见原仓库 README 以及 CONTRIBUTING

> [原项目在`forum.evageeks.org`上的帖子](https://forum.evageeks.org/thread/1393/Game-Neon-Genesis-Evangelion-2-Another-Cases/700/)

本仓库在原项目基础上添加了一些目录，它们是：

- `zh_cn`
  - `crowdin`：用于处理从 Crowdin 平台上传和下载的文本。
  - `elf_patch`：用于将码表和翻译覆盖到 EBOOT.BIN中
  - `encoding`：用于提取 EBOOT.BIN 内嵌的码表，依据词频生成新的码表，并对码表实施替换
- `parser`：\[WIP\]使用`Rust`重构的文件解析器

本仓库**中文翻译文本**按照[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)开源协议共享。

本仓库日文原文与英文翻译文本版权由原作者所有。

# 贡献
阅读[翻译贡献指南](./CROWDIN_CONTRIBUTING.md)

# 项目进度

## 二进制文件

| 名称      | 状态                                                      | 项目地址                                    |
| --------- | --------------------------------------------------------- | ------------------------------------------- |
| EBOOT.BIN | ![Crowdin](https://badges.crowdin.net/nge2/localized.svg) | [Crowdin](https://crowdin.com/project/nge2) |

## 资源文件

### 场景 EVS

| 章节 | 名称                       | 角色     | 状态 |
| ---- | -------------------------- | -------- | ---- |
| 1    | 使徒、襲来                 | 碇真嗣   |      |
| 2    | でも、この世界が好き       | 碇真嗣   |      |
| 3    | レイ、心のむこうに         | 绫波丽   |      |
| 4    | 脆いところにくちづけを     | 明日香   |      |
| 5    | 女の戦い                   | 葛城美里 |      |
| 6    | 人類補完計画               | 碇源堂   |      |
| 7    | 見果てぬ白昼夢             | 冬月耕造 |      |
| 8    | 女は炎                     | 赤木律子 |      |
| 9    | 若草の頃                   | 伊吹摩耶 |      |
| 10   | 曖昧な空                   | 日向诚   |      |
| 11   | コバルトスカイ             | 青叶茂   |      |
| 12   | VS.ゼーレ                  | 加持良治 |      |
| 13   | 心のありったけを           | 铃原冬二 |      |
| 14   | 夢から覚めれば             | 相田剑介 |      |
| 15   | 春を見たヒト               | 洞木光   |      |
| 16   | 折れた翼                   | 渚薰     |      |
| 17   | ニンゲンの手がまだ触れない | Pen Pen  |      |
| 16   | シバムラティックバランス   | 碇真嗣   |      |

# 程序设计进度
主要是预处理原脚本生成的json文件
自动化上传下载和Patch的部分

# 图片翻译进度
仍在随缘翻译中

## TODO
+ [ ] 建立完整项目结构，能够一键Patch。
+ [ ] 引入CI/CD，能够自动生成Patch应用
+ [x] 对宣发网站存档。