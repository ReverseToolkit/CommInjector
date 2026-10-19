# CommInjector

基于 [WuwaInjector](https://github.com/y0xc/WuwaInjector) 的进程注入工具，用于向 Android 进程注入 so 和 dex。`linker` 子命令用自带 linker 装载 so；so 和 dex 的映射用内核 `PROT_HIDE` 隐藏。

上游说明见 [README.WuwaInjector.md](README.WuwaInjector.md)。
