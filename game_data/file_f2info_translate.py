#!/usr/bin/env python2.7
# -*- coding: UTF-8 -*-

# Note:
# This file is a bit different to the section_*_translate files,
# in that the Japanese to be translated is BEFORE the ???.
# Put the translations in the ???
# \n is a linebreak
# \0 is the end of the string
# \' is a single quote
# The number １ to ４ starting each entry is the number of pages
# it uses to display in-game. It is unknown if the numbers are required to be in S-JIS
# for the game to parse them (currently they're in utf-8 in this file).

translate_map = {
"１\nエヴァの構造：広報公開情報\n\n　ネルフが開発した、対使徒戦用の汎用人型決戦兵器。\n　有線の電力供給で稼動。\n　内部電源のみでは５分しかもたない。\n\0\0\0\0":
'１\n Eva Mechanics: Public Information\n\n  The multipurpose humanoid decisive weapons developed by Nerv \n for use in anti-Angel combat. They operate on electric power supplied\n via cable, functional for only five minutes on internal power alone.\n\0',

"２\nエヴァの構造：一般情報\n\n　エヴァは、２０００年、南極で発見された第壱使徒を元に\nクローン再生したものである。\n　その意味で、使徒と同じような共通機構を持つ。その一例\nが、物理域にまで影響を及ぼすΑΤフィールドである。$n\n\n　エヴァと使徒との違いといえば、Σ機関と魂がなかった事\nである。\n\0\0\0\0":
'２\n Eva Mechanics: General Information \n\n Evas are clones of the First Angel, a being discovered \n  in Antarctica in the year 2000. This means that Evas have features \n  in common with the Angels. One example is the A.T. Field,  which has \n the power to influence even the laws of physics. $n\ Evas differ from Angels in that they lack both S² Engines\n and souls.\n\0',

"２\nエヴァの構造：非公開情報\n\n　エヴァとは人の形を捨てた魂の入れ物であり、自我の拡大\n＝大きな人間として具現化したものである。\n　エヴァを操作するにあたって、魂の入っていないエヴァに\n魂を入れる必要があった。\n　これをパイロットという。$n\n\n　だが、パイロットだけではエヴァは動かない。あるいは、\nきちんとした性能を発揮する事が出来ないのである。\n\0":
'２\n Eva Mechanics: Confidential Information \n\n Evas are vessels for souls that abandoned human form: egos \n magnified through embodiment as giant human beings. \n Inserting souls into the Evas — termed "pilots" — \n is a requirement for operating them. $n\ However, Evas won\'t work with a pilot alone. It\'s also \n possible that they are unable to perform properly.\n\0',

"２\nエヴァの構造：最深度情報\n\n　エヴァ＝神の肉体と魂たる人間の間に格差をなくすため、\nコアというユニットが使われた。\n　コアにはパイロットの母親の魂が入れられており、これを\n介在して操縦が出来るのである。$n\n\n　エヴァ零号機が性能的に劣っていたり、開発に難儀してい\nたのはコアのシステムがうまく作られておらず、また零号機\nパイロット綾波レイに、母親がいなかったためである。\n\0\0\0":
'２\n Eva Mechanics: Top Secret Information\n\n A unit called a core is used to eliminate any disparity between\n an Eva, the body of a god, and the soul of a human being.\n The soul of the pilot\'s mother, which is placed \n within the core, acts as a medium and makes piloting possible.。$n\n\n Due to difficulties encountered in the development of Unit-00, the core\'s \n system is poorly constructed, and the Eva falls behind in \n performance as a result. Another reason for this is \n that Unit-00\'s pilot, Rei Ayanami, does not have a mother.\n\0',

"１\nエヴァ初号機：広報公開情報\n\n　パイロットはサード・チルドレン、碇シンジ。\n　テストタイプのエヴァンゲリオンである。\n\0\0\0":
'１\nEva Unit-01： Public Information\n\n　Its pilot is the Third Child, Shinji Ikari.\n The Test Type Evangelion.\n\0',

"１\nエヴァ初号機：一般情報\n\n　初号機の開発過程において、初号機との接触実験の被験者\nとなったのは、シンジの母である碇ユイであった。\n　尚、被験者の碇ユイは、２００４年、自ら希望して初号機\nとの接触実験を行い、命を落としている。\n\0":
'１\nEva Unit-01： General Information\n\n　During Unit-01\'s developmental phase, Shinji\'s mother, Yui\n Ikari, became the test subject for Unit-01\'s contact experiment.\n　 In 2004, Yui carried out the experiment with Unit-01\n as she had hoped, but not without losing her life.\n\0',

"１\nエヴァ初号機：非公開情報\n\n　通常、エヴァのコアにはパイロットとのリンクのために、\nパイロットの母の魂が入っている。\n　初号機の場合、ユイの魂である。\n\0\0":
'１\nEva Unit-01： Confidential Information\n\n Normally, in order for the Eva\'s core to link with the pilot,\n it must contain the soul of the pilot\'s mother.\n In the case of Unit-01, that soul is Yui\'s.\n\0',

"２\nエヴァ初号機：最深度情報\n\n　ゼーレは、かねてから裏切りの気配があるゲンドウを警戒\nし、ゲンドウの息子が初号機のパイロットである事を危険視\nしている。\n　神の魂になる存在は、思い通りになる存在がいいとゼーレ\nは考えていたのである。$n\n\n　一方ゲンドウは、初号機を、自分の思い通りになる「神」\nにしようと企てている。\n\0\0\0":
'２\nEva Unit-01： Top Secret Information\n\n As Gendo has long exhibited signs of treachery, Seele treat his son\'s\n status as the pilot of Unit-01 as a potential danger.\n This is because Seele believe that a divine soul\n should come into existence only on their terms.$n\n\n However, Gendo has his own plans for becoming "God",\n which he hopes to fulfill using Unit-01.\n\0',

"１\nセカンド・チルドレン：広報公開情報\n\n　セカンド・チルドレン、惣流・アスカ・ラングレー。\n　エヴァ弐号機パイロットである。\n　ドイツと日本の血が流れるクォーターで、アメリカ国籍。\n　１４歳でドイツの大学を卒業。\n\0\0\0":
'１\nSecond Child: Public Information\n\n The Second Child, Asuka Soryu Langley.\n The pilot of Eva Unit-02.\n An American citizen, 1/4 German and 1/4 Japanese.\n Graduated from a German university at the age of fourteen.\n\0',

"１\nセカンド・チルドレン：一般情報\n\n　アスカの母、惣流・キョウコ・ツェッペリンがエヴァとの\n接触実験を行っている。\n　その結果、自分の娘を認識出来ないほどの重度の精神障害\nに陥った。\n\0":
'１\nSecond Child: General Information\n\n Asuka\'s mother, Kyoko Soryu Zeppelin, carried out a\n contact experiment with an Eva. As a result, she fell prey\n to mental illness so severe that she\n could no longer recognize her own daughter.\n\0',

"１\nセカンド・チルドレン：非公開情報\n\n　母親のエヴァとの接触実験後ほどなく、マルドゥック機関\nより、アスカは弐号機パイロットとして選出される。\n\0\0\0":
'１\nSecond Child: Confidential Information\n\n Not long after her mother\'s contact experiment with an Eva,\n Asuka was selected by the Marduk Institute to be the pilot of Unit-02.\n\0',

"１\nセカンド・チルドレン：最深度情報\n\n　アスカの母は、エヴァのコア実験の際に魂の一部、その中\nでも娘を愛する母性の部分だけがエヴァ弐号機に残された。\n　母が娘を娘と認識できなくなったのはそのせいである。\n\0\0\0\0":
'１\nSecond Child: Top Secret Information\n\n When Asuka\'s mother conducted the experiment with Eva Unit-02\'s core, only the maternal\n part of her soul, which loves her daughter above all else, was left inside the Eva.\n This is why she could not recognize her daughter for who she was.\n\0',

"１\n碇ユイ：広報公開情報\n\n　碇シンジの母であり、ゲンドウの妻。\n　２００４年に死亡。\n　享年２７歳。\n\0\0":
'１\nYui Ikari: Public Information\n\nThe mother of Shinji Ikari, and wife to Gendo　Ikari.\n She was 27 years old at the time of her death in 2004.\n\0\0',

"１\n碇ユイ：一般情報\n\n　碇ユイは、優秀な遺伝子工学の権威でもあった。\n　２００４年、開発中の初号機への接触実験を行うが、その\n実験中に死亡したとされる。\n\0\0":
'１\nYui Ikari: General Information\n\nYui Ikari was a brilliant genetic engineer and an authority in her field.\n In 2004, she performed the contact experiment on Unit-01, which\n was being developed at the time, and allegedly died during the procedure.\n\0\0',

"１\n碇ユイ：非公開情報\n\n　ユイは、被験者として接触実験を行ったがため、初号機に\nその魂を宿らせる事となった。\n　シンジが初号機パイロットとして選ばれたのも、ユイの魂\nが宿っているからである。\n\0":
'１\nYui Ikari: Confidential Information\n\n Yui conducted the experiment in the role of test subject,\n but as a result her soul became fixed inside Unit-01.\n Shinji was selected as Unit-01\'s pilot\n because Yui\'s soul dwells in the Eva still.\n\0',

"１\n碇ユイ：最深度情報\n\n　碇ユイは、ゼーレの有力者の子女の一人であり、ゼーレの\n計画を、それなりに理解出来る立場にあった。\n　ゲンドウはそれを知っており、ユイに近づいた。\n\0\0\0\0":
'１\nYui Ikari: Top Secret Information\n\nYui Ikari was the only child of an influential member of Seele and,\n in her own way, was in the position of being able to\n understand their plans. Knowing this, Gendo became acquainted with her.\n\0',

"１\n碇ゲンドウ：広報公開情報\n\n　ネルフの最高司令官であり、碇シンジの父である。\n　目的のためには、手段を選ばない冷徹な性格の持ち主で、\n部下からは少々苦手とされている。\n\0\0":
'１\nGendo Ikari: Public Information\n\nSupreme commander of Nerv and father of Shinji Ikari.\n A cool-headed personality who will use any means necessary to achieve\n his goals. His subordinates find him somewhat difficult to deal with.\n\0',

"１\n碇ゲンドウ：一般情報\n\n　かつて存在した「ゲヒルン（人工進化研究所）」の所長を\n務めていた。\n　情報操作、隠蔽工作を得意とし、ネルフの運営資金を得る\nために活動する。\n\0\0\0":
'１\nGendo Ikari: General Information\n\n Served as the chief of the former entity Gehirn (Artificial\n Evolution Laboratory). With a gift for manipulating information and\n creating cover-ups, he acts to procure operating funds for Nerv.\n\0',

"１\n碇ゲンドウ：非公開情報\n\n　ゼーレと繋がりがある碇ユイと結婚し、自らもゼーレの一\n員となってＥ計画、人類補完計画、ネルフの実行責任者など\nの要職を歴任している。\n　ゼーレの構成員になったばかりの頃、南極へ向かった葛城\n調査隊の監査役をしていた。\n\0\0":
'１\nGendo Ikari: Confidential Information\n\n Married Yui Ikari, who has connections to Seele, and in doing so became\n a member himself. Held consecutive posts as chief supervisor — among other things —\n of Project E, the Human Instrumentality Project, and Nerv. Not long after\n joining Seele, he served as statutory auditor for the Katsuragi Research Team headed to Antarctica.\n\0',

"１\n碇ゲンドウ：最深度情報\n\n　ゲンドウは、ゼーレと同じく使徒の殲滅および、人類補完\n計画を目的としていたが、その実態は死んだユイと再会する\n事を目的としている。\n　ゲンドウは反逆の意志を悟られぬよう動き続け、ゼーレは\nこれを厳しく監視し、場合によっては脅しをかけている。\n\0\0":
'１\nGendo Ikari: Top Secret Information\n\n Gendo ostensibly shares Seele\'s goals of annihilating the Angels and bringing\n about the Human Instrumentality Project. In truth, however, Gendo\n seeks to reunite with the deceased Yui. He works toward\n his goal with care to conceal his treacherous intent.\n Seele keep a close eye on him and issue threats as required.\n\0',

"１\n特務機関ネルフ：広報公開情報\n\n　使徒の調査、研究および、その殲滅を目的とする国連直属\nの特務機関である。\n　日本の第３新東京市に本部を置く。\n　第１、第２支部がアメリカに、ドイツに第３支部がある。\n\0\0\0":
'１\nSecret Agency Nerv: Public Information\n\n A secret agency under the direct supervision of the United Nations. Its objectives are to investigate, study, and eliminate the Angels. Nerv\'s headquarters are in Tokyo-3, the 1st and 2nd branches are in America, and the 3rd branch is in Germany.',

"１\n特務機関ネルフ：一般情報\n\n　政府とネルフとの関係はあまり良好ではなく、使徒が来る\nのはネルフのせいだと考えている。\n　ネルフの予算承認権は、国連の小組織である人類補完委員\n会が持っている。\n\0\0\0":
'１\nSecret Agency Nerv: General Information\n\n The relationship between the government and Nerv leaves much to be desired, as\n the former believe that Nerv are responsible for the coming of the Angels.\n The Human Instrumentality Committee, a small body within the U.N., holds\n approval authority over Nerv\'s budget.\n\0',

"１\n特務機関ネルフ：非公開情報\n\n　ネルフは、使徒を殲滅するという表向きの目的の一方で、\n人類の進化＝神への道をも目指している。\n　両方の目的達成は、一つのキーの存在によって行われる。\n　それが、エヴァである。\n\0\0\0":
'１\nSecret Agency Nerv: Confidential Information\n\n While Nerv is officially tasked with the annihilation\n of the Angels, they are also working toward the\n Way to God: the evolution of humanity.\n The Evas are the key to achieving both goals.\n\0',

"１\n特務機関ネルフ：最深度情報\n\n　ネルフ本部は、リリスを入れた黒い月の中に存在する。\n　使徒がネルフ本部を目指してやって来るのは、ターミナル\nドグマにある白い巨人、リリスに接触するためである。\n　使徒は、アダムではなく、初めからリリスを目指していた\nのである。\n\0\0\0\0":
'１\nSecret Agency Nerv: Top Secret Information\n\n Nerv Headquarters is inside the Black Moon — the container of Lilith,\n the white giant in Terminal Dogma. The Angels are heading for Nerv H.Q.\n with the aim of making contact with Lilith, not with Adam.',

"１\nマルドゥック機関：広報公開情報\n\n　該当データなし。\n\0\0":
'???',

"１\nマルドゥック機関：一般情報\n\n　エヴァンゲリオンのパイロット選出のために設けられた、\n人類補完委員会直属の諮問機関である。\n　非公開に活動しており、組織の実態は不透明である。\n\0\0":
'???',

"１\nマルドゥック機関：非公開情報\n\n　マルドゥック機関を構成する、１０８の関連企業はすべて\nダミーであり、本来そのような組織は存在しない。\n　マルドゥック機関からネルフに提出されていた報告書は、\n実はネルフ内で作成されていたものである。\n\0":
'???',

"１\nマルドゥック機関：最深度情報\n\n　マルドゥック機関による適格者選抜の偽装が必要な理由は\n適格者をゲンドウが任意に選ぶ際、表向きにそれを出さない\nためにある。\n\0\0\0\0":
'???',

"１\nゲンドウの野望：広報公開情報\n\n　特務機関ネルフの最高司令官として、サードインパクトを\n未然に防ぐため、使徒殲滅を目的とする。\n\0":
'???',

"１\nゲンドウの野望：一般情報\n\n　使徒の殲滅、および人類補完計画を遂行することを目的と\nしている。\n\0":
'???',

"１\nゲンドウの野望：非公開情報\n\n　ゲンドウは、神への道（＝人類補完計画）を目指すふりを\nしながら、その実態は、死んだユイと再会することを目的と\nしている。\n　ゲンドウが初号機にこだわり、初号機によって神への道を\n開こうとしていたのは、その一点に拘っていたからである。\n\0\0":
'???',

"２\nゲンドウの野望：最深度情報\n\n　ゼーレが、ゼーレの意のままに扱える「神」を用意しよう\nとしていたのに対して、ゲンドウはゲンドウで、自分の思い\n通りに動く「神」を作ろうと、己の目的のために裏で計画を\n進めていた。$n\n\n　ゲンドウは復元中のアダムの欠片と融合し、レイ＝リリス\nとの融合を経て初号機との融合（ユイとの再会）を果たそう\nと思っている。\n\0\0\0":
'???',

"１\nネルフの歴史：広報公開情報\n\n　“使徒”と呼ばれる物体に対する調査、研究、および殲滅\nを目的として国連直属の特務機関として、２０１０年に結成\nされた。\n\0\0":
'???',

"２\nネルフの歴史：一般情報\n\n　ネルフは、ゼーレの目的を体現する実行組織であり、最も\n重要な組織である。\n　ゲヒルン時代とは異なり、半ば公然とした組織である。\n　セカンドインパクトによって、ゼーレはむしろ先鋭化し、\n強力に計画を推進し始めた。$n\n\n　ともかくも、神の奇跡は本当に実在し、神に限りなく近い\n存在であるアダムも実在したのである。\n\0":
'???',

"２\nネルフの歴史：非公開情報\n\n　アダムの発見は、確信となって、ゼーレの背中を押した。\n　黒い月、即ち箱根の発掘とリリスの発見、人工進化研究所\nの設立と、それに続くゲヒルンの構築、人類限界説の流布、\n人類補完委員会の設立、使徒との戦闘をにらんだ国連主導の\n世界構築。$n\n\n　これらは、セカンドインパクトに前後し一斉に行われた。\n　そして、アダムの復活計画＝Ｅ計画。\n　聖書で言うアダムの肋骨から創ったというそれは、エヴァ\nと呼ばれた。\n　これらは順次行われ、そして今に続くことになる。\n\0\0\0\0":
'???',

"４\nネルフの歴史：最深度情報\n\n　人類補完委員会。\n　本来は国連の小委員会でしかないそれは、実質上、世界を\n手玉にとるゼーレの下部組織である。$n\n\n　この委員会は人類限界説を根拠とし、その対処を検討する\n存在として設立され、自前の研究機関を持つことになった。\nこれを人工進化研究所という。$n\n\n　人工進化研究所はアダムの破片を手に入れた事で、ゼーレ\nのより強い介入を受け、組織体系を強化、実質上の直轄下部\n組織、秘密組織ゲヒルンとなった。$n\n\n　ゲヒルンは準備組織であり、次なる組織であるネルフの下\n地となった。\n\nそうして、ネルフが作られた。\n\0":
'???',

"１\n人類補完計画の内容：広報公開情報\n\n　該当データなし。\n\0\0\0\0":
'???',

"１\n人類補完計画の内容：一般情報\n\n　人類補完計画は、Ｅ計画、アダム計画と並ぶネルフの三大\n計画の一つで、ゼーレがもっとも重要視するものである。\n\0\0\0":
'???',

"３\n人類補完計画の内容：非公開情報\n\n　人類補完計画とは、不死を目指す計画である。\n　エヴァは、ゼーレにとって重要な存在で、神への道を開く\n一つの鍵だった。\n　なぜならそれが、神にもっとも近いアダムのコピーだった\nからである。$n\n\n　まだ足りないものこそいくつかあるが、その部分さえどう\nにかすれば、人は神か、あるいはそれに限りなく近い存在を\n手に入れることが出来ると思われた。\n　それは人の足りない部分を補完する事で、「神への道」が\n開かれるというゼーレの教義でもある。$n\n\n　人は神を拾ったら、何をするか。\n\n　自分も神になろうと思ったのである。\n\0\0":
'???',

"３\n人類補完計画の内容：最深度情報\n\n　使徒との戦いが行われる一方、人が神へ至る道も、計画化\nされて進んでいた。\n　それは一つに、Σ機関の搭載による魂の座である神の肉体\n＝エヴァの完成である。$n\n\n　次に魂の混入。\n　最後に、天敵であり保安装置である“ロンギヌスの槍”を\n消滅させる事で、誰によっても滅する事の出来ない神に近い\nものが完成する。\n　あるいは神そのものが。$n\n\n　ゼーレはこの人の作りし神によって、優良な者（自分達）\nを神に近いところへ導くつもりであった。\n\0\0\0\0":
'???',

"１\nゲヒルン：広報公開情報\n\n　該当データなし。\n\0\0":
'???',

"１\nゲヒルン：一般情報\n\n　ネルフの前身ともいえる調査組織。\n　２０１０年、赤木ナオコ博士によってマギシステム完成。\n　それと同時にゲヒルンは解体される。\n　赤木ナオコを除き、構成員は全計画の遂行組織として特務\n機関ネルフに移行した。\n\0\0\0\0":
'???',

"１\nゲヒルン：非公開情報\n\n　ゲヒルンとは、人工進化研究所の事で、ゼーレの裏向きの\n機関の名称である。\n　人工進化研究所は国連に認められた下部組織であり、人工\n進化の研究を表向きの目的として行っていた。\n\0\0\0":
'???',

"１\nゲヒルン：最深度情報\n\n　ゲヒルンの目的は、アダム再生計画（Ｅ計画）。\n\n　実際はコピーを作る事＝エヴァを作る事であった。\n　そして、より実行に近づき拡大したスタイルとしてネルフ\nを結成した。\n\0\0":
'???',

"１\nゼーレ：広報公開情報\n\n　該当データなし。\n\0\0\0\0":
'???',

"１\nゼーレ：一般情報\n\n　人類補完計画を遂行するため、特務機関ネルフを背後から\n操る秘密結社。\n　ネルフの資金のほとんどは、ここから出ている。\n\0\0":
'???',

"２\nゼーレ：非公開情報\n\n　中世暗黒期に誕生した、秘教秘密結社。\n　元は、宗教教団であった。$n\n\n　ゼーレはゆるやかに、しかし確実に勢力を伸ばし、ついに\n１９００年代中頃には、最後の抵抗勢力を叩き潰して、人類\n世界を裏から支配する隠然たる勢力となった。\n\n　これは２０１５年現在も続いている。\n\0":
'???',

"２\nゼーレ：最深度情報\n\n　裏死海文書を手に入れたゼーレは、それまで先祖の世迷い\n話程度にしか思っていなかった教義にもう一度目を向ける。\n　神の奇跡を、預言という形で目の当たりにした事で、信心\nに立ち返ったといっていい。$n\n\n　教義とは、アダム・カダモンへの道、すなわち不老不死の\n神に近づく事である。\n\0\0":
'???',

"１\nΑΤフィールド：広報公開情報\n\n　使徒とエヴァだけが発生させられる、絶対的な物理防壁。\n　使徒が発するΑΤフィールドの前には、地球上のあらゆる\n通常兵器は歯が立たない。\n　使徒との戦闘においては、エヴァがΑΤフィールドを中和\nする。\n\0\0":
'???',

"１\nΑΤフィールド：一般情報\n\n　人間にもΑΤフィールドはあるが、使徒ほどの強力な力を\n持たないと、物理力に影響を与えられない。\n\0\0\0":
'???',

"１\nΑΤフィールド：非公開情報\n\n　魂の座が肉体で、それを決定するのが、ΑΤフィールド＝\n自我（他者と隔てる心の壁）である。\n　人が人たりえるのは、人がそう思っているからである。\n\0\0":
'???',

"１\nΑΤフィールド：最深度情報\n\n　ΑΤフィールドの拡大、それの極限は、無制限の自我＝神\nであり、その前では、人は自我を崩壊してＬＣＬに戻る。\n\0":
'???',

"１\nΣ機関：広報公開情報\n\n　該当データなし。\n\0\0\0\0":
'???',

"１\nΣ機関：一般情報\n\n　“スーパーソレノイド機関”という、使徒が持つ永久動力\n機関である。\n　自己修復機能、変形機能などの生物の常識を超えた使徒の\n能力は、これによるものと思われる。\n\0":
'???',

"１\nΣ機関：非公開情報\n\n　Σ機関の理論は、葛城博士によって提唱された。\n　世界は螺旋で出来ており、ＤＮＡの構造と同じその形から\nエネルギーを得ている。\n　ここから螺旋のエネルギー＝無尽蔵のエネルギーを得よう\nとするエンジンとしてΣ機関の存在が構想されていた。\n\0\0":
'???',

"１\nΣ機関：最深度情報\n\n　生命の実。\n　エヴァがアダムと同等の存在になるために、足りない物の\n一つである。\n\0\0\0\0":
'???',

"１\n使徒：広報公開情報\n\n　該当データなし。\n\0\0":
'???',

"１\n使徒：一般情報\n\n　生物・非生物の概念を超えた、正体不明の人類の敵。\n　全てを破壊尽くせる圧倒的な攻撃力と、人類が持つ全ての\n通常兵器を寄せ付けない驚異的な防御力を有す。\n　第３新東京市地下、ジオフロントに存在するネルフ本部を\n目指して侵攻して来る。\n\0\0\0\0":
'???',

"２\n使徒：非公開情報\n\n　アダムから生まれた生命こそが使徒である。\n　\n　一方、リリスから誕生したのは人類である。$n\n\n　使徒は、リリスから誕生した生物と異なり、巨大で単一と\nいう性質を有する生物である。\n　アダムベースの生命は、本来地球で芽吹き、そしてそこで\n繁栄するはずの生命だった。\n\0":
'???',

"３\n使徒：最深度情報\n\n　一つの星に二つの生命の種はいらない。\n　だから、片方は排除する。$n\n\n　裏死海文書に記された内容通りに、アダムベースの生命は\n己の生存をかけた生存競争を挑んできた。\n　あるものはリリスにアクセスする事で全生命にリセットを\nかけようと、あるものは何も考えず、あるものは始祖アダム\nを取り返すために。$n\n\n　それぞれの生存繁栄戦略の元、アダムベースの生命である\n使徒は、動き出すことになった。\n\0\0":
'???',

"１\nアダム：広報公開情報\n\n　該当データなし。\n\0\0\0\0":
'???',

"１\nアダム：一般情報\n\n　第壱使徒。\n　ターミナルドグマで磔にされている白い巨人。\n\0":
'???',

"１\nアダム：非公開情報\n\n　アダムは、第一始祖民族によって地球に着床した、生命の\n始源たる存在である。\n　葛城調査隊により南極で発見されたが、調査中、Σ機関の\n人為的暴走により、ばらばらの肉片となって退化した。\n\0\0\0":
'???',

"２\nアダム：最深度情報\n\n　アダムには魂がなかった。\n　セカンドインパクトの時に、肉体がばらばらになり、魂は\nどこかへ飛んでいたのである。$n\n\n　魂は後にゼーレによって回収、受肉され、これは渚カヲル\nという形になる。\n　カヲルにしてみれば、エヴァは自分の身体の一部だから、\n自由に扱える。ただし、中には入れない。なぜならその身体\nには、（パイロットの母の）魂があるからである。\n\0\0":
'???',

"１\n死海文書：広報公開情報\n\n　該当データなし。\n\0\0":
'???',

"１\n死海文書：一般情報\n\n　使徒の出現時期が記されていた預言書、未来記である。\n\0\0\0\0":
'???',

"３\n死海文書：非公開情報\n\n　ゼーレは、巨額の富を持つが故に、芸術や学術のパトロン\n集団という側面も持っていた。\n　ゲヒルン（人工進化研究所）などは、全てゼーレの出資に\nよるものである。$n\n\n　元が宗教教団であったためか、ゼーレは、己の宗教の遺構\n調査の資金援助等も良くこなした。\n\n　この中でゼーレにとっても、人類にとっても重要な転機と\nなるものが発掘される。$n\n\n　裏死海文書である。\n\0":
'???',

"４\n死海文書：最深度情報\n\n　生命の種（始源の存在）と保安装置であるロンギヌスの槍\nの使い方を、第一始祖民族が記したマニュアル。あるいは、\n運用時の計画書を、宗教集団が己の教義に当てはめつつ写本\nしたもの。$n\n\n　それが、裏死海文書である。\n\n　過去の計画書で今も動きつづける点では、預言書である。$n\n\n　それまでゼーレ自身は、断片的にその内容を知り、存在を\n信じていたが、まさか実在し、意味ある預言が記され、完全\nに近い形で出てくるとは、思ってもいなかったのである。$n\n\n　それはすぐさま本部に送られ、そして、事実自体はすぐに\n情報操作されて隠蔽されることになった。\n　後に公表された重要でないものを死海文書、ゼーレが持ち\n去り隠蔽したものを、裏死海文書と呼ぶ。\n\0\0":
'???',

"１\n第一始祖民族：広報公開情報\n\n　該当データなし。\n\0\0":
'???',

"１\n第一始祖民族：一般情報\n\n　使徒を創ったとされる存在。\n　その目的の詳細は不明である。\n\0":
'???',

"３\n第一始祖民族：非公開情報\n\n　最初に宇宙人がいた。\n　“第一始祖民族”とも言われるその人型種族は、銀河系の\n各地に生命の種をばら蒔き始めた。$n\n\n　その理由がなんだったのか。\n　何を目指していたのか。\n\n　今となっては、分からない。\n　はっきりしている事は複数の種がばら蒔かれた事である。$n\n\n　運の悪い事に、そのうち二つが、偶然、同じ星に落ちた。\n　白い月のアダム。\n　そして、黒い月のリリスである。\n\0\0\0\0":
'???',

"１\n第一始祖民族：最深度情報\n\n　第一始祖民族は、月というキャリア（運び屋）の中に完全\nなる空洞（これも月）を作り、そこに始源の存在という種を\n入れて宇宙に送り出した。\n　それこそが、彼らのテクノロジーであり、また使徒や人類\nからすれば、彼らは神とも言える。\n\0\0\0\0":
'???',

"１\n第二使徒：広報公開情報\n\n　該当データなし。\n\0\0":
'???',

"１\n第二使徒：一般情報\n\n　第二使徒はリリスという。\n　黒い月を運ぶ、月（地球の衛星となった）から来た。\n　第二使徒は、月と地球の接触によるジャイアントイン\nパクト（＝ファーストインパクト）を引き起こした。\n\0\0\0":
'???',

"１\n第二使徒：非公開情報\n\n　ターミナルドグマに磔にされている白い巨人であり、猿や\nイルカ、最終形態としてリリン、即ち人類を生み出した。\n　なお、ＬＣＬは、リリスの体液である。\n\0\0\0\0":
'???',

"２\n第二使徒：最深度情報\n\n　リリスには魂がなかった。\n　そして、その魂は、レイに宿っていた。$n\n\n　レイの肉体は、コピーで幾らでも作れた。だが、レイその\nものが常に一体しか存在しえなかったのはこのためである。\n　レイは、ユイの肉体のコピーではあっても、魂はそうでは\nなかったのである。\n\0\0":
'???',

"２\nセカンドインパクト：広報公開情報\n\n　２０００年９月１３日、南極に巨大隕石が落下した。\n　これによる大爆発で発生した大津波と溶け出した氷により\n海抜は数十メートル上昇。\n　南半球諸国あわせて２０億以上の人々が死亡。$n\n\n　爆発のエネルギーによって地軸はねじ曲がり、地球規模で\n気象が変化し、日本は常夏の国になってしまった。\n　このセカンドインパクトにより、世界各地で干ばつ、洪水\n噴火や異常気象が発生。\n　各国に経済恐慌と内戦が起きた。\n\0\0\0":
'???',

"２\nセカンドインパクト：一般情報\n\n　２０００年、人類は最初の使徒と呼称する人型の生命体を\n南極で発見。\n　その調査中に原因不明の大爆発が発生した。\n　この惨事がセカンドインパクトである。$n\n\n　一般に知られている隕石衝突による説は、情報操作された\nものである。\n\0\0":
'???',

"１\nセカンドインパクト：非公開情報\n\n　セカンドインパクトの原因となった、第壱使徒アダムは、\n南極で葛城調査隊により発見された。\n　ゼーレからの出資で葛城調査隊はアダムとロンギヌスの槍\nが入った白い月を発見する事になる。\n\0":
'???',

"３\nセカンドインパクト：最深度情報\n\n　人間は、もう一つの生命の種であるアダムを目覚めさせて\nしまった。\n　葛城調査隊はロンギヌスの槍を使い必死に再封印しようと\nするが、失敗。$n\n\n　最終的にはΣ機関の人為的暴走と思われる（詳細は調査隊\nが全滅しているため不明）現象で、完全な破局＝ΑΤフィー\nルド消失による全生命のリセットと、アダムベースの生態系\n構築だけは阻止される形になった。\n　これを、セカンドインパクトという。$n\n\n　この事件でアダムは、ばらばらの肉片となってしまった。\n\0":
'???',

"１\nサードインパクト：広報公開情報\n\n　該当データなし。\n\0\0":
'???',

"１\nサードインパクト：一般情報\n\n　使徒が、ターミナルドグマの白い巨人アダムと接触すると\nセカンドインパクト同等の爆発が起こると言われている。\n\0":
'???',

"１\nサードインパクト：非公開情報\n\n　ターミナルドグマのリリス、またはアダムのどちらかでも\n使徒が接触すると、サードインパクトが発生するとされる。\n　実際には人類補完計画の発動となる。\n\0\0\0\0":
'???',

"１\nサードインパクト：最深度情報\n\n　サードインパクトの正体は、人が人としての境界を失い、\n人が融けることを言う。\n　生命は終末を迎え（終末の内容は不明）ΑΤフィールドを\n失う（人間の形も維持出来なくなる）。\n\0":
'???',

"１\nロンギヌスの槍：広報公開情報\n\n　該当データなし。\n\0\0\0\0":
'???',

"１\nロンギヌスの槍：一般情報\n\n　南極で、白い月からアダムと共に発見された。\n　ロンギヌスの槍は本来、生命の種とセットになった、保安\n装置である。\n\0\0":
'???',

"３\nロンギヌスの槍：非公開情報\n\n　意志を持った槍であり、自力で移動する能力も持つ一種の\n生命体である。$n\n\n　ロンギヌスの槍は、神に近い＝不死の力を持った生命の種\n（始源の存在）の動きを停止させる事が出来るアイテムで、\n生命の種（始源の存在）が神に及ばないその理由でもある。\n　第一始祖民族は生命の種（始源の存在）が自分達の目的に\n沿わないときの対策としてこれを用意していた。$n\n\n　リリスと対になっているロンギヌスの槍は、恐らくファー\nストインパクトの時の衝撃で、リリスから抜けて離れ離れに\nなったと思われる。\n　この槍は今も見つかっていない。ひょっとすれば破壊され\nたのかもしれない。\n\0":
'???',

"１\nロンギヌスの槍：最深度情報\n\n　碇ゲンドウやゼーレが、神への道を開くために、それまで\nやってきたリリスの増殖を、最終段階で一時的に止めるため\nネルフはアダムとセットになっていたロンギヌスの槍を輸送\nする事になる。\n\0":
'???',

"１\nダミープラグ：広報公開情報\n\n　該当データなし。\n\0\0":
'???',

"１\nダミープラグ：一般情報\n\n　ダミーシステム用に開発された、エントリープラグ。\n　パイロットがいなくても、エヴァを、パイロットがそこに\nいるかのように思わせる事で起動させる事が出来る。\n\0\0":
'???',

"３\nダミープラグ：非公開情報\n\n　ダミープラグには人格がコピーされているが、魂はコピー\n出来ない。$n\n\n　なぜ出来ないのか、どうやればいいのか。\n　それは、ゼーレやネルフの技術部門にとって、神への道を\n探るために重要な研究テーマであり、長年にわたって対処が\n研究されていた。\n　その失敗例が、ユイやアスカの母である。$n\n\n　ダミープラグとは、その途中で生まれてきたものである。\n\0\0\0":
'???',

"１\nダミープラグ：最深度情報\n\n　ダミーシステムとは、研究の末に開発された人工的な魂で\nある。\n　ただ機能的には大幅に劣り、エヴァを動かすという程度の\n機能しか持たせられなかった。\n\0":
'???',

"２\nジオフロント：広報公開情報\n\n　第３新東京市の地下に存在する謎の巨大な地下空間の事。\n　この空間にネルフ本部施設が建築されている。\n　直径６キロ、高さ０．９キロの半球型の空間だが、現在は\nその８９％が埋没している。$n\n\n　地上の集光ブロックから光ファイバーにより太陽光が送り\n込まれ、地上と同様の明るさを保つ。\n　建築されているのは、ネルフの施設が殆どだが、民間人の\n避難シェルターも存在する。\n\0\0\0\0":
'???',

"１\nジオフロント：一般情報\n\n　ネルフ本部があるジオフロントとは別に、南極にも、ジオ\nフロントは存在した。\n　そして、その南極のジオフロントの中から、アダムと称さ\nれる第壱使徒が発見された。\n\0\0\0":
'???',

"１\nジオフロント：非公開情報\n\n　ジオフロントの正体は、ネルフ本部が存在し第３新東京市\nの地下にあるものを「黒い月」、南極のものを「白い月」と\nいう。\n　黒い月にはリリス、白い月にはアダムが入っている。\n\0\0\0":
'???',

"２\nジオフロント：最深度情報\n\n　まず、アダムを入れた白い月が地球に落ち、本来別の星系\nに行くはずだった黒い月が地球重力に囚われて、地面に激突\nしてバウンドした後、地球の周囲を巡る衛星になった。\n　リリスを入れた黒い月は、残骸だけ残して天に残り、中の\n種たるリリスは、地球に着床した。$n\n\n　リリスが落ちたのは、今で言う南極付近であったと思われ\nるが、そのあとのプレート移動によって、最終的には日本の\n箱根付近にまで移動することになる。\n　箱根（現第３新東京市）地下の大空洞はそれであり、後の\nネルフ本部は、ここに造られることになった。\n\0\0\0\0":
'???',

}
