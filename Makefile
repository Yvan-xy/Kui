obj-m    :=kui.o

kui-objs += ./src/a.o ./src/file.o ./src/elf32.o ./src/sha1.o ./src/elf64.o ./src/sign.o
kui-objs += ./src/test64.o ./src/signtest.o

KDIR    := /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)
ccflags-y := -std=gnu11

all: inSub
	$(MAKE) -C $(KDIR) M=$(PWD) modules 

sub:
	cd sign && make 

inSub: sub
	cp sign/check /sbin/check

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm /sbin/check && cd sign && make clean