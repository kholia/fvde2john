Usage
-----

$ tar -xJf fvde-1.raw.tar.xz

$ sudo kpartx -v -a fvde-1.raw
add map loop2p1 (253:5): 0 1048496 linear /dev/loop2 40

$ sudo ./fvdetools/fvdeinfo -p openwall /dev/mapper/loop2p1
fvdeinfo 20160918

Core Storage information:

Physical volume:
	Size:				536829952 bytes
	Encryption method:		AES XTS

Logical volume:
	Size:				167772160 bytes
