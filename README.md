Interface Mirroring
==================

This guide explains how to configure and use the Interface mirroring driver.
<br/>


Build & Install
---------------
```
1. Run: make all (In order to clean if necessary, run: make clean) 
2. Make sure both 'Interface_mirroring.ko" and "test_write" were created.
3. Install driver: sudo insmod interface_mirroring.ko
4. In order to follow dmesg log (On a different terminal), run: journalctl -kf.
5. Run test program: ./test_write: ( Do it on a different terminal then the driver)
	1. Add the following format: iface_in_name, iface_out_name, listen_protocol, ip. e.g - wlan0 eth0 udp 192.168.12.248;
	2. You can add multiple lines of the above
6. Uninstall driver: sudo rmmod interface_mirroring

```
