---
title: Malware Analysis Notes - Classic sample OpenProcess injection
time: 2026-1-30 1:00:00
categories: [research]
tags: [malware analysis, process injection]
image: ../assets/posts/29-1-2026-SimpleOpenProcess-Analysis/process_hacker1.png
---

Hello everyone, in this series I would like to document my learning process on malware analysis step by step, from the basics to advancing my skills.

In this post, I will statically and dynamically analyze a simple sample of a process injection that uses the Win32 API to inject shellcode(execute MessageBoxA) into a process.

This is an educational sample created by me. Real malware uses techniques that are a thousand times more advanced than what you will find here. I hope you enjoy it. 

```shell
❯ file sample.exe
sample.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
	    md5: 9f48c935f2ecc9001a7beaa3189b9d2c
```
## Static analysis

First, since it is a PE32+ file, executable for Windows, I will use PE-Bear to analyze its structure.

![pebear](../assets/posts/29-1-2026-SimpleOpenProcess-Analysis/pebear.png)

Looking at imports, we see that it has 19 entries in KERNEL32.dll.

```shell
OpenProcess - open a target process
VirtualAllocEX - alloc virtual memory on proc
WriteProcessMemory - write shellcode into that memory
VirtualProtectEx - turn memory section RX
```

This is a simple and classic detectable workflow that injectors follow to execute instructions in the memory of another process.

#### Use radare2 to obtain the shellcode in the .data section.

To obtain the address where the shellcode is located, we have to establish an entry point. In this case, since it is so simple, we can obtain the entry point in the function fcn.140001010(main).

After a little analysis of the disassembly, we can see this fragment of instructions:

![memcpy](../assets/posts/29-1-2026-SimpleOpenProcess-Analysis/memcpy.png)

call `sub.api_ms_win_crt_private_l1_1_0.dll_memcpy ; void *memcpy(void *s1, const void *s2, size_t n)`  refers to the WriteProcessMemory call, where the shellcode is copied into the created section.

Now we trace the R15 and RSI registers to determine the offset of the address where *s2(shellcode) is stored.

```python
>>> hex(0x140008018-0x4f64)
'0x1400030b4'
```

```
[0x140001010]> px 332 @  0x1400030b4
- offset -   B4B5 B6B7 B8B9 BABB BCBD BEBF C0C1 C2C3  456789ABCDEF0123
0x1400030b4  0100 0000 0000 0000 0000 0000 fc48 81e4  .............H..
0x1400030c4  f0ff ffff e8cc 0000 0041 5141 5052 5148  .........AQAPRQH
0x1400030d4  31d2 6548 8b52 6056 488b 5218 488b 5220  1.eH.R`VH.R.H.R 
0x1400030e4  4d31 c948 0fb7 4a4a 488b 7250 4831 c0ac  M1.H..JJH.rPH1..
0x1400030f4  3c61 7c02 2c20 41c1 c90d 4101 c1e2 ed52  <a|., A...A....R
0x140003104  488b 5220 4151 8b42 3c48 01d0 6681 7818  H.R AQ.B<H..f.x.
0x140003114  0b02 0f85 7200 0000 8b80 8800 0000 4885  ....r.........H.
0x140003124  c074 6748 01d0 508b 4818 448b 4020 4901  .tgH..P.H.D.@ I.
0x140003134  d0e3 564d 31c9 48ff c941 8b34 8848 01d6  ..VM1.H..A.4.H..
0x140003144  4831 c041 c1c9 0dac 4101 c138 e075 f14c  H1.A....A..8.u.L
0x140003154  034c 2408 4539 d175 d858 448b 4024 4901  .L$.E9.u.XD.@$I.
0x140003164  d066 418b 0c48 448b 401c 4901 d041 8b04  .fA..HD.@.I..A..
0x140003174  8841 5841 585e 5948 01d0 5a41 5841 5941  .AXAX^YH..ZAXAYA
0x140003184  5a48 83ec 2041 52ff e058 4159 5a48 8b12  ZH.. AR..XAYZH..
0x140003194  e94b ffff ff5d e80b 0000 0075 7365 7233  .K...].....user3
0x1400031a4  322e 646c 6c00 5941 ba4c 7726 07ff d549  2.dll.YA.Lw&...I
0x1400031b4  c7c1 0000 0000 e815 0000 0075 2068 6176  ...........u hav
0x1400031c4  6520 6265 656e 2070 776e 6564 203a 2900  e been pwned :).
0x1400031d4  5ae8 0700 0000 6173 6461 7364 0041 5848  Z.....asdasd.AXH
0x1400031e4  31c9 41ba 4583 5607 ffd5 4831 c941 baf0  1.A.E.V...H1.A..
0x1400031f4  b5a2 56ff d500 0000 0000 0000            ..V.........
```

We already have the shellcode. In the future, I will explain how we can dump the opcodes and disassemble them to obtain the actual instructions (only if it is raw in the code).

## Dynamic analysis

For the dynamic analysis, I will be using a Windows 10 lab.

I use Process Hacker. I do not plan to do an exhaustive analysis because, in this case, it is a simple shellcode that calls MessageBoxA.

![process_hacker1](../assets/posts/29-1-2026-SimpleOpenProcess-Analysis/process_hacker1.png)

Here you can see how the sample code calls the messagebox within another process. Let's analyze this a little further.

![process_hacke](../assets/posts/29-1-2026-SimpleOpenProcess-Analysis/process_hacker2.png)

You can see how a new memory section with RX permissions (PAGE_EXECUTE_READ) has been created. Upon analyzing it, we see that the hexadecimal value matches the one we obtained in the static analysis.

[OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)

[VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)

[WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)

Thanks for reading this far and apologies for my non-technical language (I'm not very good at it)...


