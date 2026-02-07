# Injector

Android 平台进程注入工具，使用 Rust 编写，通过 NDK 交叉编译。

## 功能

- 监控 Android 进程启动事件（通过读取 `liblog.so` 的 event log）
- 基于 `ptrace` 的进程注入能力

## 构建

需要配置 Android NDK 交叉编译工具链，详见 `scripts/build.sh`。

## 致谢

- 进程监控（`proc_monitor`）的实现参考了 [vvb2060](https://github.com/vvb2060) 提供的代码：[am_proc_start.cpp](https://gist.github.com/vvb2060/a3d40084cd9273b65a15f8a351b4eb0e#file-am_proc_start-cpp)
- [xDL](https://github.com/nicedayzhu/xDL) — Android 动态链接器加载库
- [KittyMemoryEx](https://github.com/MJx0/KittyMemoryEx) — Android 内存工具库

## License

MIT
