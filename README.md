# YukiZygisk

**English** | [简体中文](README.zh-CN.md)

YukiZygisk is a standalone, kernel-based Zygisk implementation for rooted Android devices. It runs Zygisk and ZN native modules, with a built-in WebUI for checking status and changing settings.

[Download](https://github.com/Rouyashiki/YukiZygisk/releases/latest) · [Report an issue](https://github.com/Rouyashiki/YukiZygisk/issues)

## Requirements

- An ARM64 device with a supported GKI kernel. Packages cover supported variants of 5.10, 5.15, 6.1, 6.6 and 6.12; the installer checks for a matching kernel automatically.
- KernelSU, YukiSU or APatch. Magisk and devices running multiple root implementations are currently unsupported.
- A manager with module WebUI support to use the settings interface.

## Installation

1. Disable any other Zygisk implementation, including YukiSU's built-in YukiZygisk if enabled.
2. Download `YukiZygisk-…-all-kmi-arm64-v8a.zip` from [Releases](https://github.com/Rouyashiki/YukiZygisk/releases/latest). Choose the module ZIP, not the source code archive.
3. Open your root manager, go to **Modules**, and install the ZIP from local storage.
4. Reboot, then open YukiZygisk's **WebUI** from the module page to check its status.

If the installer cannot identify your kernel's KMI, use **Volume Up** to cycle through the packaged KMIs and **Volume Down** to confirm. After installation, only the selected KMI's kernel module is kept to save space. Reinstall after switching kernels if the KMI changes or needs manual selection again.

## Usage

- Install the Zygisk or ZN native modules you want through your root manager, then reboot.
- Use the WebUI to view loaded modules, check injection status and adjust settings.
- Use the module's **Action** button to view its current status and recent startup logs.
- Update, disable or uninstall YukiZygisk through your root manager, then reboot to apply the change.

If something goes wrong, [open an issue](https://github.com/Rouyashiki/YukiZygisk/issues) with your device model, Android and kernel versions, root implementation, steps to reproduce and the output from the Action button.

## License

Original work is licensed under [Apache-2.0](LICENSE); [GPL-2.0](LICENSE-GPL-2.0) applies when used with the Linux kernel. Third-party components retain their original licenses. See [NOTICE](NOTICE) for credits and details.
