---
title: '贡献指南'
layout: ../layouts/MarkdownPostLayout.astro
---
# EVA 翻译贡献指南（V1.0）

- [EVA 翻译贡献指南（V1.0）](#eva-翻译贡献指南v10)
  - [`Paratranz`上的待翻译内容](#paratranz上的待翻译内容)
    - [EBOOT.BIN：游戏可执行文件中的SJIS日文字符](#ebootbin游戏可执行文件中的sjis日文字符)
      - [翻译长度限制](#翻译长度限制)
    - [EVS：事件脚本（Event Script）文件](#evs事件脚本event-script文件)
      - [字数限制](#字数限制)
    - [FREE](#free)
    - [GAME](#game)
  - [术语表](#术语表)
  - [标点符号](#标点符号)
    - [中英混合](#中英混合)
    - [多行文本](#多行文本)
    - [特殊字符](#特殊字符)
    - [格式说明符 Format Specifiers](#格式说明符-format-specifiers)
  - [参考资料](#参考资料)
    - [中文互联网](#中文互联网)
    - [英文](#英文)
    - [日文](#日文)
- [附录](#附录)
  - [chunk\_20](#chunk_20)

## `Paratranz`上的待翻译内容

### EBOOT.BIN：游戏可执行文件中的SJIS日文字符

+ 该部分翻译内容有严格字数限制，详见下文
+ 部分为DEBUG菜单可不翻译

优先翻译：
见任务列表

#### 翻译长度限制

尽量确保翻译字符串长度<=原字符串长度

对于原字符串长度，ASCII 字符、半角日文（翻译中禁止使用）和英文标点 1 字节，其他字符（如日文和全角英文以及全角标点） 2 字节。

对于翻译后的字符串，中文字符占2字节，其余同上。

请自行估计，勿使翻译后字符串长度超过原字符串长度。

> 比如，ペンペン四个日文字符占 8 字节，翻译为Pen Pen一共 7 个 ASCII 字符占 7 字节，可以接受。

### EVS：事件脚本（Event Script）文件

剧情中的主要事件和随机事件，也是UP主Langley_D在其相关[主线剧情](https://space.bilibili.com/523663/channel/collectiondetail?sid=1165421)视频中主要录制的部分。

#### 字数限制

据原项目作者注释

```
text limits to prevent crashes:
    - 3 lines
    - 34 bytes per line
    - 42 bytes per line with half width
    - 103 bytes + 1 null terminator (excluding whitespace)
```
  + 一页最多103字节（由下三角∇分隔）
  + 一页**不超过三行**（如果一行超过17个汉字会自动换行。此时若再添加`\n`会多换一行。三行以外的内容会渲染到画面以外无法阅读）
就是说如果连续五十个汉字没出现∇就要自己加一个
为了断句可以添加换行符，但对于长句子可以**不需要手动`\n`换行符**以防止溢出文本框，游戏会自动换行！
![](/media/21cd8cb4a613a49e65627e943b93e172.png)
> 此处换行导致第三行文本消失于画面外

![](/media/c9715952cd05c31e444d2f4c39256cdd.png)
![](/media/348d7e551f83a30c382625691845b1c8.png)


### FREE
+ `info`：包括所有的**机密信息**，包括EVA设定；
+ `tuto`：教程，含有大量游戏中的专有名词，可以先行敲定。

### GAME

游戏中日常部分的随机文本，量大。


## 术语表

参见`术语`部分

下面仅列出参考资料
+ [人名](https://zh.wikipedia.org/wiki/%E6%96%B0%E4%B8%96%E7%BA%AA%E7%A6%8F%E9%9F%B3%E6%88%98%E5%A3%AB#%E6%BC%94%E5%91%98%E8%A1%A8)
    + 当仅出现姓或名时翻译为对应的姓或者名。
+ [使徒名](https://zh.wikipedia.org/wiki/%E4%BD%BF%E5%BE%92_(%E6%96%B0%E4%B8%96%E7%BA%AA%E7%A6%8F%E9%9F%B3%E6%88%98%E5%A3%AB)#TV%E7%89%88%E5%92%8C%E6%BC%AB%E7%95%AB%E7%89%88)
    + 使徒名统一采用意译

## 标点符号

基本原则：尽量适应中文标点标准，同时保持排版美观

- `。`：照抄。
- `、`：对于简短的标题，保留顿号。对于长句，若原文顿号起逗号的作用，改为逗号。
- `…`：
  - 原文`…`单独出现的情况尽量改为`……`
  - 原文`…。`连用的现象改为`……`，`…？`连用的现象改为`？`
- `「`：使用直角引号，与原文一致。
- 不可见字符一律按原样复制。
- 请勿使用英文`~`，使用`～`(U+FF5E FULLWIDTH TILDE)
- 请勿使用英文`-`，使用破折号的一半`—`（除非原文如此）

### 中英混合

为节约空间，中文与英文字符之间不加空格

原文中使用全角英文字符时尽量使用全角英文字符。

### 多行文本

字符串长度及其分布尽量与原文一致。
有些多余空格用于排版，亦应保留。

### 特殊字符

特殊含义的西文字符，**请勿翻译**。

- A Greek `Θ` `(ShiftJIS: 0x83, 0xA6)` the game renders as `J.`
- A Greek `Α` `(ShiftJIS: 0x83, 0x9F)` the game renders as `A.`
- A Greek `Τ` `(ShiftJIS: 0x83, 0xB1)` the game renders as `T.`
- A Greek `Ν` `(ShiftJIS: 0x83, 0xAB)` the game renders as `N²`
- A Greek `Σ` `(ShiftJIS: 0x83, 0xB0)` the game renders as `S²`
- The Fullwidth Latin`Ｓ` `(ShiftJIS: 0x82, 0x72)` the game renders as `S`
- The character `▽` is used to start a new "page" of dialog box text.

### 格式说明符 Format Specifiers

下述字符串**请勿翻译**，按原样保留即可。

- `%s` 字符串
- `%f` 浮点型
- `%d` 整型

游戏使用的自定义格式说明符：

- **$a** 似乎是主动参与者/主语/玩家
- **$b** 似乎是被动参与者/物品所有者
- **$c** 似乎是入侵者/覆盖主语/非玩家主语
- **$d** 似乎是一个数字（或可能是天使序数）
- **$n** 似乎表示一个超级换行符，触发新页面的开始，而 `\n` 触发新行的开始。（见于 free/info）
- **$o** 似乎是主语拥有的物品/对象
- **$p** 似乎是被动参与者拥有的物品/对象

## 参考资料

### 中文互联网

网络上存在有关该游戏部分内容的已汉化版本，可以用于了解该游戏内容。
翻译时不应照抄，以免侵犯他人著作权。

- [游戏攻略](https://tieba.baidu.com/p/8273551416)(沢田纲吉)
- [主线剧情](https://space.bilibili.com/523663/channel/collectiondetail?sid=1165421)(Langley_D)
- [日常剧情](https://space.bilibili.com/4272978/channel/collectiondetail?sid=26092&ctype=0)(幸好我 CP 没事)
- [机密情报](https://tieba.baidu.com/p/1879040823)(洗手见天使)

### 英文

- [原英化项目](https://forum.evageeks.org/thread/1393/Game-Neon-Genesis-Evangelion-2-Another-Cases/700/)
- [英文游戏指南](https://gamefaqs.gamespot.com/psp/930008-neon-genesis-evangelion-tsukurareshi-sekai-another-cases/faqs/45735)

### 日文

- [新世紀エヴァンゲリオン 2  -造られしセカイ-@Wiki](https://w.atwiki.jp/eva2psp/)
- [新世紀エヴァンゲリオンの用語一覧](https://ja.m.wikipedia.org/wiki/%E6%96%B0%E4%B8%96%E7%B4%80%E3%82%A8%E3%83%B4%E3%82%A1%E3%83%B3%E3%82%B2%E3%83%AA%E3%82%AA%E3%83%B3%E3%81%AE%E7%94%A8%E8%AA%9E%E4%B8%80%E8%A6%A7)
- [实况视频](https://www.nicovideo.jp/user/46082281/series/435227?ref=user_series)

# 附录
## chunk_20
武器介绍部分一行最多不能超过8个中文
![](/media/8e46eeb3ae608b7c83c42a3b3157cef1.png)
![](/media/b3bfac33e7234ca0ac9c935073d4b791.png)
