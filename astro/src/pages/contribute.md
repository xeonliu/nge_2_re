---
title: '贡献指南'
layout: ../layouts/MarkdownPostLayout.astro
---
# EVA 翻译贡献指南（V0.3）

- [EVA 翻译贡献指南（V0.3）](#eva-翻译贡献指南v03)
  - [参考资料](#参考资料)
    - [中文互联网](#中文互联网)
    - [英文](#英文)
    - [日文](#日文)
  - [术语表](#术语表)
    - [人名](#人名)
    - [使徒名](#使徒名)
    - [关卡名](#关卡名)
    - [字符串长度限制（重要）](#字符串长度限制重要)
    - [标点符号](#标点符号)
    - [中英混合](#中英混合)
    - [多行文本](#多行文本)
    - [特殊字符](#特殊字符)
    - [格式说明符 Format Specifiers](#格式说明符-format-specifiers)

## 参考资料

### 中文互联网

网络上存在有关该游戏部分内容的已汉化版本，可以用于了解该游戏内容。
不能照抄，考虑如何避免侵犯他人著作权（联系？）

- [游戏攻略](https://tieba.baidu.com/p/8273551416)(沢田纲吉)
- [主线剧情](https://space.bilibili.com/523663/channel/collectiondetail?sid=1165421)(Langley_D)
- [日常剧情](https://space.bilibili.com/4272978/channel/collectiondetail?sid=26092&ctype=0)(幸好我 CP 没事)
- [机密情报](https://tieba.baidu.com/p/1879040823)(洗手见天使)

### 英文

- [原英化项目](https://forum.evageeks.org/thread/1393/Game-Neon-Genesis-Evangelion-2-Another-Cases/700/)

### 日文

- [新世紀エヴァンゲリオン 2 　-造られしセカイ-@Wiki](https://w.atwiki.jp/eva2psp/)
- [新世紀エヴァンゲリオンの用語一覧](https://ja.m.wikipedia.org/wiki/%E6%96%B0%E4%B8%96%E7%B4%80%E3%82%A8%E3%83%B4%E3%82%A1%E3%83%B3%E3%82%B2%E3%83%AA%E3%82%AA%E3%83%B3%E3%81%AE%E7%94%A8%E8%AA%9E%E4%B8%80%E8%A6%A7)

## 术语表

逐渐补充至 Crowdin

### 人名

人名以[Wikipedia](https://zh.wikipedia.org/wiki/%E6%96%B0%E4%B8%96%E7%BA%AA%E7%A6%8F%E9%9F%B3%E6%88%98%E5%A3%AB#%E6%BC%94%E5%91%98%E8%A1%A8)为准
| 中文 | 日文 |
| ----------- | ----------- |
|碇真嗣|碇 シンジ|
|绫波丽|綾波 レイ|
|惣流・明日香・兰格雷|惣流・アスカ・ラングレー|
|葛城美里|葛城 ミサト|
|渚薰|渚 カヲル|
|赤木律子|赤木 リツコ|
|碇源堂|碇 ゲンドウ|
|冬月耕造|冬月 コウゾウ|
|加持良治|加持 リョウジ|
|伊吹摩耶|伊吹 マヤ|
|日向诚|日向 マコト|
|青叶茂|青葉シゲル|
|铃原冬二|鈴原 トウジ|
|相田剑介|相田 ケンスケ|
|洞木光|洞木 ヒカリ|
|Pen Pen|ペンペン|

当仅出现姓或名时翻译为对应的姓或者名。

应当全部加入 Crowdin Glossary 以获得提示。

### 使徒名

使徒名统一采用意译，见[Wikipedia](<https://zh.wikipedia.org/wiki/%E4%BD%BF%E5%BE%92_(%E6%96%B0%E4%B8%96%E7%BA%AA%E7%A6%8F%E9%9F%B3%E6%88%98%E5%A3%AB)#TV%E7%89%88%E5%92%8C%E6%BC%AB%E7%95%AB%E7%89%88>)
|中文|日文|
|--|--|
|亚当|アダム|
|莉莉丝|リリス|
|水天使|サキエル|
|昼天使|シャムシェル|
|雷天使|ラミエル|
|鱼天使|ガギエル|
|……|……|

详见 Crowdin Glossary

### 关卡名

关于“芝村平衡”：https://detail.chiebukuro.yahoo.co.jp/qa/question_detail/q1230875672

### 字符串长度限制（重要）

- 在 SHIFT-JIS 编码中，ASCII 字符 1 字节，其他字符（如日文和特殊符号） 2 字节。

- 翻译后文本 ASCII 字符 占 1 字节，其他字符 2 字节。

请自行估计，**勿使翻译后字符串长度超过原字符串长度**。

比如，`ペンペン`四个日文字符占 8 字节，翻译为`Pen Pen`一共 7 个 ASCII 字符占 7 字节，可以接受。

### 标点符号

基本原则：尽量适应中文标点标准，同时保持排版美观

- `。`：照抄。
- `、`：对于简短的标题，保留顿号。对于长句，若原文顿号起逗号的作用，改为逗号。
- `…`：
  - 原文`…`单独出现的情况尽量改为`……`
  - 原文`…。`连用的现象改为`……`，`…？`连用的现象改为`？`
- `「`：使用直角引号，与原文一致。
- 不可见字符一律按原样复制。

### 中英混合

为节约空间，中文与英文字符之间不加空格

### 多行文本

字符串长度及其分布尽量与原文一致。
有些多余空格用于排版，亦应保留。

### 特殊字符

> 以下部分大量参考<https://github.com/rezual/nge_2_re>
>
> 具体规范不同

部分特殊含义的西文字符，**请勿翻译**。

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

- `$a` seems to be the active participant/subject/player
- `$b` seems to be the passive participant/owner-of-object
- `$c` seems to be an intruder/overriding subject/non-player subject
- `$d` seems to be a number (or maybe angel ordinal)
- `$n` seems to denote a super-line-break that triggers the start of a new page while `\n` triggers the start of a new line.
- `$o` seems to be an item/object in subject's possession
- `$p` seems to be an item/object in passive participant's possession
