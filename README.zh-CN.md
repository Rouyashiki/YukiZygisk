# YukiZygisk

[English](README.md) | **简体中文**

YukiZygisk 是一个独立的、基于内核的 Zygisk 实现，让已 root 的 Android 设备运行 Zygisk 模块，也支持 ZN 原生模块。内置 WebUI，可以查看运行状态和调整设置。

[下载](https://github.com/Rouyashiki/YukiZygisk/releases/latest) · [反馈问题](https://github.com/Rouyashiki/YukiZygisk/issues)

## 使用要求

- ARM64 设备，使用受支持的 GKI 内核。安装包覆盖 5.10、5.15、6.1、6.6 和 6.12 的受支持版本，安装时会自动检查是否匹配。
- 已安装 KernelSU、YukiSU 或 APatch。目前不支持 Magisk，也不支持多种 root 方案共存。
- 使用支持模块 WebUI 的管理器，以便打开设置界面。

## 安装

1. 关闭其他 Zygisk 实现；如果启用了 YukiSU 内置的 YukiZygisk，也需要先关闭。
2. 从 [Releases](https://github.com/Rouyashiki/YukiZygisk/releases/latest) 下载 `YukiZygisk-…-all-kmi-arm64-v8a.zip` 模块安装包，不要下载源码压缩包。
3. 打开 root 管理器，进入**模块**页面，选择从本地安装这个 ZIP。
4. 重启设备，在模块页面打开 YukiZygisk 的 **WebUI**，确认运行状态。

## 使用

- 需要使用的 Zygisk 或 ZN 原生模块，照常通过 root 管理器安装，然后重启。
- 在 WebUI 中查看已加载的模块、注入状态和调整设置。
- 点击模块的**操作（Action）**按钮，查看当前状态和最近的启动日志。
- 更新、停用或卸载 YukiZygisk，都在 root 管理器中操作，完成后重启生效。

遇到问题时，请[提交 Issue](https://github.com/Rouyashiki/YukiZygisk/issues)，附上机型、Android 与内核版本、root 方案、复现步骤，以及操作按钮显示的输出。

## 许可证

原创代码采用 [Apache-2.0](LICENSE)，用于 Linux 内核时适用 [GPL-2.0](LICENSE-GPL-2.0)。第三方组件保留各自的许可证，鸣谢和详细说明见 [NOTICE](NOTICE)。
