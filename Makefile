obj-m += interface_mirroring.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	$(CC) test_write.c -o test_write
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm test_write