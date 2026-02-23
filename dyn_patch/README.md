# Reverse Engineering

Reverse Core Logic in C.

2026/02/23

Main Progress: 
- LBN Logic Found: Can load from Memstick in the future.

```
path_to_lbn	.text	08985FE4	00000334	00000060		R	.	.	.	.	.	B	T	.	.
```

- Logo Loading Logic Found

Can add other logos

- Main Menu (4 Options Logic Found?)
    - See Chat log. Didn't dig into it

- Decomp?

- IDA parse C file
```shell
psp-gcc -E -P -D_PSP_FW_VERSION=660     -D"__attribute__(x)="     -D"__extension__="     -D"__inline__="     -D"inline="     -D"static="     -D"__asm__(x)="     -D"nullptr=0"     -D"__builtin_va_list=void*"     -I$PSPDEV/psp/sdk/include     allpsp.h -o psp_signatures_final.h
```
- scripts for clean up C headers
- PPSSPP export symbol
- prxtool idc file export

```
prxtool --idcout --xmlfile psplibdoc.xml -o output.idc input.prx
```