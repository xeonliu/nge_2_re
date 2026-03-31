#import "@preview/min-manual:0.3.0": *

#show heading: set text(font: ("Heiti SC"))
#set text(font: ("Times New Roman", "Songti SC", "Source Han Sans", "PingFang SC"))

#show: manual.with(
  title: "EVA2 汉化补丁",
  description: "PSP游戏《新世纪福音战士2：被创造的世界》使用指南",
  authors: "main_void <@xeonliu>",
  package: "nge_2_re:0.1.20260427",
  license: "GPL-3.0",
  logo: image("assets/logo.png")
)


#v(1fr)
#outline()
#v(1.2fr)
#pagebreak()


= 补丁简介

经过“EVA2汉化计划”团队历时 2 年的汉化与测试，《新世纪福音战士2：被创造的世界 ～Another Cases～》的中文测试补丁终于和大家见面！

- 游戏名称：《新世紀エヴァンゲリオン 2 造られしセカイ -another cases-》
- 中文名称：《新世纪福音战士2：被创造的世界 ～Another Cases～》
- 发行时间：2006年4月27日（平装版/十周年纪念版）
- 发行平台：PlayStation Portable
- 汉化内容：全文本（90%机翻 + 10%人工） / 部分 UI / 部分图片
- 汉化发布时间：2026年4月27日（测试版）

#callout(
  title: "注意事项",
  background: rgb("#fff3cd"),
  text: rgb("#856404"),
  icon: "exclamation-triangle"
)[
  + 禁止用于商业用途，转载需注明出处。
  + 由于本次发布为测试版，游戏存在崩溃可能，敬请谅解。
  + 如有问题可在 GitHub Issue 或评论区中反馈。
]


= 成员名单

以下为参与本次汉化的人员名单（排名不分先后）：

#table(
  columns: (auto, 1fr),
  [*职务*], [*成员*],
  [统筹], [main_void, hanDragon20],[翻译],[hanDragon20, Liana384, Frykte, Belfraw, Tianying.exe, カロモリモキナエ, Asuka, mel, Laolv000, zxlraw, yokuse],
  [校对],[hanDragon20, Frykte, Belfraw, カロモリモキナエ, Asuka, mel, Laolv000],
  [程序],[main_void],
  [美工], [main_void, Belfraw],
)

#pagebreak()

= 支持版本

#table(
  columns: (auto, auto, auto, 1fr),[*版本号*], [*原始镜像 CRC32*], [*补丁后镜像 CRC32*], [*类型*],
  [ULJS-00064], [1C8AF7DD],[等发布后填写], [平装],
  [ULJS-00061],[CD46A4EC], [等发布后填写], [10周年纪念装]
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
  ),[应用补丁需要前文所述的日文原始镜像。原始镜像可以通过原始 UMD 和破解后的 PSP 获取，网络上已有大量教程，不再赘述。]
)

本补丁以 `xdelta3` 格式发布。打补丁需要原始游戏镜像。

可以在网页端使用 #url("https://kotcrab.github.io/xdelta-wasm/")[xdelta-wasm] 在线应用补丁（不消耗流量）。

== PPSSPP 模拟器
- iOS 设备推荐将 CPU 核心模式改为 **“解释器”**，以减少 JIT 带来的性能损失。

== PSP 实机
- 需要已破解设备（推荐 *ARK-4*），可直接运行补丁版镜像。


= 功能介绍

在游戏开始前，会显示调试菜单：
- 使用O键启用/禁用功能。
- 使用方向键切换。

按下 START 键后，首先会显示汉化成员名单。随后游戏开始。


= 原理介绍

`EBOOT.BIN` 是使用 C 语言编写的启动器，负责启动原始游戏程序并对内存中的数据和指令进行修改，使得部分函数调用跳转到启动器中的函数。

通过这种方法，实现自定义字体的加载，文字编码映射的修改以及翻译文本的替换。除此以外，对于存档界面的语言参数也进行了修改。另一方面，启动器也负责显示和处理开始的调试菜单。

游戏中具体资源文件的修改主要依靠 #url("https://github.com/rezual/nge_2_re")[rezual/nge_2_re] 的解析器实现。


= 发布说明

该测试版发布后，预计根据反馈，按照 **每月一版** 的进度进行更新。

- 敬请关注 Bilibili 发布信息。
- 可以在 GitHub Release 获取最新补丁。


= 开源协议

- 中文翻译文本按照 #url("https://creativecommons.org/licenses/by-sa/4.0/")[CC-BY-SA 4.0] 协议开源。
- 代码程序按照 #url("https://www.gnu.org/licenses/gpl-3.0.html")[GPL-3.0] 协议开源。
- 补丁文件仅供非商业免费使用。


= 转载声明

欢迎转载，请保留汉化信息，并以任何方式推荐给你最好的朋友。

*反对一切以本汉化补丁牟利的情况*，包括付费下载、回帖可见、支付虚拟币等。如果遇到任何游戏中的程序、翻译问题，请到本发布贴或 GitHub 留言。

#pagebreak()

= 版权声明

注册商标和服务标志均为其各自拥有者的财产。

- 游戏中内嵌字体使用 *寒蝉全圆体*（SIL Open Font License 1.1）。
- 图片中使用到的字体包括 *思源宋体*（SIL Open Font License 1.1）、*鹭霞文楷*（SIL Open Font License 1.1）。

“PlayStation”、“PlayStation Portable”、“PlayStation Shapes 标志”、“SHARE FACTORY”、“Play Has No Limits”和“PlayStation Productions”均为 Sony Interactive Entertainment Inc. 的注册商标或商标。

“SONY”为 Sony Group Corporation 的注册商标或商标。


= 免责声明

#callout(
  title: "免责声明",
  background: rgb("#f8f9fa"),
  icon: "information-circle"
)[
  本汉化组提醒您：在使用汉化补丁前，请您务必仔细阅读并透彻理解本声明。您可以选择不使用汉化补丁，但如果您使用汉化补丁，您的使用行为将会视为对本声明的全部内容认可。

  + 汉化补丁仅为游戏《新世紀エヴァンゲリオン 2 造られしセカイ -another cases-》进行中文本地化服务，任何试图使用汉化补丁进行其他用途所造成的后果自负。
  + 汉化补丁仅供非商业免费使用，发布方式为 GitHub Release，如果您在其他地方所找到和使用的汉化补丁或使用任何第三方软件所导致的任何结果，汉化组对其概不负责，亦不承担任何法律责任。
  + 汉化补丁不包括游戏源文件，本站不以打包镜像形式发布补丁，任何用户擅自改动游戏和补丁文件所造成的后果，请用户自行承担。
  + 本站不为《新世紀エヴァンゲリオン 2 造られしセカイ -another cases-》游戏镜像提供任何渠道的下载方式。请从正版渠道获取游戏 UMD 镜像。
  + 任何使用本汉化补丁的行为所有可能导致的违反 EVA、Bandai 官方 ToS（Term of Service 服务条款）及其所带来的官方处理结果，汉化组对其概不负责，亦不承担任何法律责任。
  + 汉化补丁坚决遵守和维护官方 ToS（Term of Service 服务条款），一切违反官方 ToS 的行为所导致的结果请用户自行负责。
  + 对上述需用户自行承担后果的，汉化组不承担任何民事乃至刑事法律责任。以上免责声明的最终解释权归汉化组所有。
]