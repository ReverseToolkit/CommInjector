# CommInjector

基于 [WuwaInjector](https://github.com/y0xc/WuwaInjector) 的进程注入工具，用于向 Android 进程注入 so 和 dex。`linker` 子命令用自带 linker 装载 so。`--hider maps` 做用户态匿名重映射。内核 `PROT_HIDE` 默认开启，`--no-kernel-hide` 关掉。

上游说明见 [README.WuwaInjector.md](README.WuwaInjector.md)。
