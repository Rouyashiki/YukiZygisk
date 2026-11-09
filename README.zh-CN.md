# YukiZygisk

<img align="right" src="webui/icon.svg" width="220" alt="YukiZygisk logo">

[English](README.md) | **简体中文**

YukiZygisk 是一个独立的、基于内核的 Zygisk 实现，让已 root 的 Android 设备运行 Zygisk 模块，也支持 ZN 原生模块。内置 WebUI，可以查看运行状态和调整设置。

[下载](https://github.com/Rouyashiki/YukiZygisk/releases/latest) · [反馈问题](https://github.com/Rouyashiki/YukiZygisk/issues)

## 使用要求

- ARM64 设备，使用受支持的 GKI 内核。安装包覆盖 5.10、5.15、6.1、6.6、6.12 和 6.18 的受支持版本，安装时会自动检查是否匹配。
- 已安装 KernelSU、YukiSU 或 APatch。目前不支持 Magisk，也不支持多种 root 方案共存。
- 使用支持模块 WebUI 的管理器，以便打开设置界面。

## 安装

1. 关闭其他 Zygisk 实现；如果启用了 YukiSU 内置的 YukiZygisk，也需要先关闭。
2. 从 [Releases](https://github.com/Rouyashiki/YukiZygisk/releases/latest) 下载 `YukiZygisk-…-all-kmi-arm64-v8a.zip` 模块安装包，不要下载源码压缩包。
3. 打开 root 管理器，进入**模块**页面，选择从本地安装这个 ZIP。
4. 重启设备，在模块页面打开 YukiZygisk 的 **WebUI**，确认运行状态。

如果安装时无法识别内核的 KMI，按**音量上键**循环切换安装包内的 KMI，按**音量下键**确认。安装完成后仅保留选中 KMI 的内核模块，节省存储空间。更换内核后，若 KMI 改变或仍需手动选择，请重新安装模块。

### KernelSU late-load

YukiZygisk 支持 KernelSU 的 [late-load 模式](https://kernelsu.org/guide/module.html#late-load-mode)。先安装并启用模块，再运行 KernelSU 的 late-load 流程。`late-load.sh` 只记录待激活状态，不加载 YukiZygisk 的 LKM，也不启动注入器。**请在 late-load 完成且系统可操作后，在 KernelSU 中手动选择软重启。** 这次软重启期间，`post-fs-data.sh` 确认 Android 和 Zygote 已停止后才加载经过认证的核心，随后由 KernelSU 重新启动 Android。启动成功后消耗待激活标记；失败或中断会保留标记，供下次到达同一阶段时重试。仅重启 Zygote 或 `system_server`（包括其他模块触发的重启）不会重放 `post-fs-data.sh`，无法激活核心。

即使 LKM 尚未加载，WebUI、模块描述和**操作（Action）**输出也会提示等待激活。系统配置所需的 Zygote 报告注入成功后，提示会消失；内核安全模式下也会撤下提示，因为软重启无法解除该保护。重复执行 `late-load.sh` 或其 `boot-completed.sh` 阶段均不会启动核心。YukiZygisk 不会自动重启 Android。

启动校验会贯穿 LKM 加载和守护进程就绪阶段，并检查同一轮 Android 停止状态。如果 KernelSU 等待脚本超时、提前恢复了 Android，本次激活会中止，保留待激活标记供下一次手动软重启重试；已经加载的 LKM 在激活完成前不允许注入。待激活时仍可保存配置，设置会在激活后生效。

Late-load 不会补注入已经运行的原生服务，ZN 原生目标需要重新执行后才能注入。模块安装和更新仍遵循 root 管理器原有的暂存流程，此功能不启用热安装。

## 使用

- 需要使用的 Zygisk 或 ZN 原生模块，照常通过 root 管理器安装，然后重启。
- 在 WebUI 中查看已加载的模块、注入状态和调整设置。
- 点击模块的**操作（Action）**按钮，查看当前状态和最近的启动日志。
- 更新、停用或卸载 YukiZygisk，都在 root 管理器中操作，完成后重启生效。

对于通过 `ZYGISK_ENABLED` 检测 Zygisk 的 KernelSU 系管理器，YukiZygisk 会在其进程完成 specialize 后设置 `ZYGISK_ENABLED=1`，通过 KernelSU 注册的管理器 UID 识别目标，不依赖包名。无需手动 `export`；此兼容不会设置全局 shell 变量，也不会改变其他模块的脚本环境。

遇到问题时，请[提交 Issue](https://github.com/Rouyashiki/YukiZygisk/issues)，附上机型、Android 与内核版本、root 方案、复现步骤，以及操作按钮显示的输出。

## 许可证

原创代码采用 [Apache-2.0](LICENSE)，用于 Linux 内核时适用 [GPL-2.0](LICENSE-GPL-2.0)。第三方组件保留各自的许可证，鸣谢和详细说明见 [NOTICE](NOTICE)。
