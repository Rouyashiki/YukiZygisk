# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
#
# YukiZygisk - Top-level build wrapper for the standalone repository.
#
# License: Author's work under Apache-2.0; when used as a kernel module
# (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
#
# Author: Rouyashiki Developers

KERNEL_DIR := $(CURDIR)/kernel

.PHONY: all modules clean

all: modules

modules:
	$(MAKE) -C $(KERNEL_DIR) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) clean
