
ifdef VERSION
obj-m +=  tx2_uncore_pcie-${VERSION}.o
else
obj-m +=  tx2_uncore_pcie.o
endif

DIR=$(PWD)

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(DIR) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(DIR) clean
