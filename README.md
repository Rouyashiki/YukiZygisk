# YukiZygisk

<img align="right" src="webui/icon.svg" width="220" alt="YukiZygisk logo">

**English** | [简体中文](README.zh-CN.md)

YukiZygisk is a standalone, kernel-based Zygisk implementation for rooted Android devices. It runs Zygisk and ZN native modules, with a built-in WebUI for checking status and changing settings.

[Download](https://github.com/Rouyashiki/YukiZygisk/releases/latest) · [Report an issue](https://github.com/Rouyashiki/YukiZygisk/issues)

## Requirements

- An ARM64 device with a supported GKI kernel. Packages cover supported variants of 5.10, 5.15, 6.1, 6.6, 6.12 and 6.18; the installer checks for a matching kernel automatically.
- KernelSU, YukiSU or APatch. Magisk and devices running multiple root implementations are currently unsupported.
- A manager with module WebUI support to use the settings interface.

## Installation

1. Disable any other Zygisk implementation, including YukiSU's built-in YukiZygisk if enabled.
2. Download `YukiZygisk-…-all-kmi-arm64-v8a.zip` from [Releases](https://github.com/Rouyashiki/YukiZygisk/releases/latest). Choose the module ZIP, not the source code archive.
3. Open your root manager, go to **Modules**, and install the ZIP from local storage.
4. Reboot, then open YukiZygisk's **WebUI** from the module page to check its status.

If the installer cannot identify your kernel's KMI, use **Volume Up** to cycle through the packaged KMIs and **Volume Down** to confirm. After installation, only the selected KMI's kernel module is kept to save space. Reinstall after switching kernels if the KMI changes or needs manual selection again.

### KernelSU late-load

YukiZygisk supports KernelSU's [late-load mode](https://kernelsu.org/guide/module.html#late-load-mode). Install and enable the module before running KernelSU's late-load flow. `late-load.sh` only records pending activation: it does not load YukiZygisk's LKM or start the injector. **After late-load finishes and Android is responsive, manually choose Soft reboot in KernelSU.** During that soft reboot, `post-fs-data.sh` loads the authenticated core only after Android and Zygote have stopped, before KernelSU starts them again. Successful startup consumes the pending marker; an interrupted or failed attempt remains retryable at this same stage. Restarting only Zygote or `system_server`, including a restart triggered by another module, does not replay `post-fs-data.sh` and cannot activate the core.

The WebUI, module description and **Action** output show the activation reminder even while the LKM is deliberately absent. The reminder clears after the required Zygotes report injection, or while kernel safe mode is active because a soft reboot cannot clear that protection. Repeating `late-load.sh` or its `boot-completed.sh` stage never starts the core. YukiZygisk does not restart Android automatically.

Startup checks the same stopped-runtime generation through LKM loading and daemon readiness. If KernelSU stops waiting for a script and resumes Android early, activation aborts and keeps the pending marker for another manual soft reboot; an already loaded LKM cannot inject before activation completes. Settings can still be saved while activation is pending and take effect when the core activates.

Late-load does not inject into already running native services. ZN native targets need to execute again before injection can take effect. Module installation and updates still use the root manager's usual staging flow; this does not enable hot installation.

## Usage

- Install the Zygisk or ZN native modules you want through your root manager, then reboot.
- Use the WebUI to view loaded modules, check injection status and adjust settings.
- Use the module's **Action** button to view its current status and recent startup logs.
- Update, disable or uninstall YukiZygisk through your root manager, then reboot to apply the change.

If something goes wrong, [open an issue](https://github.com/Rouyashiki/YukiZygisk/issues) with your device model, Android and kernel versions, root implementation, steps to reproduce and the output from the Action button.

## License

Original work is licensed under [Apache-2.0](LICENSE); [GPL-2.0](LICENSE-GPL-2.0) applies when used with the Linux kernel. Third-party components retain their original licenses. See [NOTICE](NOTICE) for credits and details.
