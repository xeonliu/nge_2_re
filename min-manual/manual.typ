#import "@preview/min-manual:0.3.0": *

#show heading: set text(font: ("Heiti SC"))
#set text(font: ("Times New Roman", "Songti SC", "Source Han Sans", "PingFang SC"))

#show: manual.with(
  title: "EVA2 汉化补丁",
  description: "PSP游戏《新世纪福音战士2：被创造的世界》使用指南",
  authors: "main_void <@xeonliu>",
  package: "nge_2_re:0.1.0",
  license: "GPL-3.0",
  logo: image("assets/logo.png")
)


#v(1fr)
#outline()
#v(1.2fr)
#pagebreak()


= 致谢

/* Example simulating a snippet in another file or location.
#let feature(
  title: none,
  date: datetime.today(),
  color: luma(250),
  size: auto,
) = {}
*/
#extract(
  "feature",
  from: read("manual.typ")
)

= 成员名单

以下为参与本次汉化的人员名单（排名不分先后）

#table(
  columns: (auto, 1fr),
  [], [*成员*],
  [统筹], [main_void, hanDragon20],
  [翻译], [hanDragon20, Liana384, Frykte, Belfraw, Tianying.exe, カロモリモキナエ, Asuka, mel, Laolv000, zxlraw, yokuse],
  [校对], [hanDragon20, Frykte, Belfraw, カロモリモキナエ, Asuka, mel, Laolv000],
  [程序], [main_void],
  [美工], [main_void, Belfraw],
)

= 支持版本

#table(
  columns: (auto, auto, 1fr),
  [版本号], [CRC32], [类型],
  [ULJS-00064], [1C8AF7DD], [平装],
  [ULJS-00061], [CD46A4EC], [10周年纪念装]
)


= 使用方法

#callout(
  title: "Note",
  text: ( title: (fill: blue) ),
  background: (
    fill: none,
    stroke: (left: 3pt + blue),
    outset: (left: 1em, bottom: 0.45em),
    inset: (left: 0pt),
  ),
  [应用补丁需要前文所述的日文原始镜像。原始镜像可以通过原始UMD和破解后的PSP获取，网络上已有大量教程，不再赘述。]
)

补丁使用`xdelta3`生成。在电脑端可以使用如下网页进行应用。



= 功能介绍

在游戏开始前，会显示调试菜单，使用X键启用/禁用功能。

按下START键后，首先会显示汉化成员名单。随后游戏开始。


= 原理介绍

`EBOOT.BIN`是使用C语言编写的启动器，负责启动原始游戏程序并对内存中的数据和指令进行修改，使得部分函数调用跳转到启动器中的函数。
通过这种方法，实现自定义字体的加载，文字编码映射的修改以及翻译文本的替换。除此以外，对于存档界面的语言参数也进行了修改。
另一方面，启动器也负责显示和处理开始的调试菜单。

游戏中具体资源文件的修改主要依靠#url("https://github.com/rezual/nge_2_re")[rezual/nge_2_re]的解析器实现。

- 字体生成使用#url("https://github.com/tpunix/pgftool")[tpunix/pgftool]

- 反汇编使用Ghidra和IDA Pro

- 插件编写依赖PSPDEV项目及其提供的PSPSDK

- 游戏中字体使用“寒蝉全圆体”，遵循OFL协议

= 开源协议

中文翻译文本按照CC-BY-SA 4.0协议开源，
程序按照GPL-3.0协议开源。

= 使用到的第三方项目


#arg("name: <- type | type | type <required>")[
  Required argument.
]
#arg("name: <- type | type | type")[
  Optional argument.
]
#arg("name: -> type | type | type")[
  Possible output types.
]
#arg("name: <- type | type | type -> type | type <required>")[
  Possible input and output types.
]
#arg("```typ #feature(name)``` -> type | type | type")[
  Syntax highlight.
]
#arg("```typ #set feature(name)```")[
  No input nor output types.
]
#arg("name: <- type | type | type | type | type | type | type | type | type | type | type | type | type | type | type | type <required>")[
  Long list of input types.
]
#arg("name: -> type | type | type | type | type | type | type | type | type | type | type | type | type | type | type | type <required>")[
  Long list of output types.
]
#arg("name: <- type | type | type | type | type | type | type | type -> type | type | type | type | type | type | type | type <required>")[
  Long list of input and output types.
]

#pagebreak()


= Paper-friendly Links

#url("https://typst.app")[This link is clickable on screens and generates a
footnote for print visibility.]

= 发布

该测试版发布后，按照每月一版的进度进行更新。

敬请关注Bilibili发布信息。

可以在GitHub Release 获取最新补丁。

= Package URLs

#grid(
  columns: (auto, auto),
  gutter: 1em,
  [*LuaRocks:      *], pkg("https://luarocks.org/modules/alerque/decasify"),
  [*Typst Universe:*], univ("decasify"),
  [*Python PyPi:   *], pip("decasify"),
  [*Rust crate:    *], crate("decasify"),
  [*GitHub repo:   *], gh("alerque/decasify"),
)


= Terminal Simulation

```term
user@host:~$ cd projects/
user@host:~/projects$ sudo su
Password:
root@host:~/projects# rm foo
rm: cannot remove 'foo': No such file or directory
```


= Code Example

```eg
A #emph[Typst] code *example*
```


= Level 1
== Level 2
=== Level 3
==== Level 4
===== Level 5
====== Level 6


= Heading References <ref>

This is tye @ref section, and the next one is the @callout section.


= Callout <callout>

#callout[Simple default callout.]

#callout(title: "Title")[Callout with title]

// More icon names in https://heroicons.com/
#callout(background: blue, text: white, icon: "exclamation-triangle")[
  Blue callout with white text and custom icon.]

#callout(
  title: "Note",
  text: ( title: (fill: blue) ),
  background: (
    fill: none,
    stroke: (left: 3pt + blue),
    outset: (left: 1em, bottom: 0.45em),
    inset: (left: 0pt),
  ),
  [GitHub-ish customized callout.]
)

#pagebreak()


= Page Space

#lorem(50)

#lorem(70)

#lorem(50)

#lorem(70)

#lorem(50)

#lorem(70)

#lorem(24)
