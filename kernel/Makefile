# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
#
# YukiZygisk - External-module build wrapper for the kernel directory.
#
# License: Author's work under Apache-2.0; when used as a kernel module
# (or linked with the Linux kernel), GPL-2.0 applies for kernel compatibility.
#
# Author: Anatdx

ifneq ($(KERNELRELEASE),)
include $(src)/Kbuild
else

KDIR ?= /lib/modules/$(shell uname -r)/build
KBUILD_ARGS := M=$(CURDIR)
# Keep Linux 6.18 external-module outputs beside the sources, as on older DDKs.
ifeq ($(notdir $(patsubst %/,%,$(KDIR))),android17-6.18)
KBUILD_ARGS += MO=$(CURDIR)
endif

.PHONY: all modules clean

all: modules

modules:
	$(MAKE) -C $(KDIR) $(KBUILD_ARGS) modules

clean:
	$(MAKE) -C $(KDIR) $(KBUILD_ARGS) clean

endif
