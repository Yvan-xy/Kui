obj-m    := kui.o

kui-objs += ./src/kui.o ./src/file.o ./src/elf32.o ./src/sha1.o ./src/elf64.o ./src/sign.o
kui-objs += ./src/test64.o ./src/signtest.o

KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)
ccflags-y := -std=gnu11 -Wno-declaration-after-statement

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
