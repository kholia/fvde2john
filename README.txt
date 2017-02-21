Usage
-----

$ tar -xJf fvde-1.raw.tar.xz

$ sudo kpartx -v -a fvde-1.raw
add map loop2p1 (253:5): 0 1048496 linear /dev/loop2 40

$ sudo fvdetools/fvdeinfo -p dummy /dev/mapper/loop2p1
fvdeinfo 20160918

$fvde$16$e7eebaabacaffe04dd33d22fd09e30e5$41000$e9acbb4bc6dafb74aadb72c576fecf69c2ad45ccd4776d76
...

Give this hash string to JtR jumbo to crack.

Help
----

https://github.com/libyal/libfvde/wiki

https://github.com/libyal/libfvde/wiki/Troubleshooting

Build
-----

https://github.com/libyal/libfvde/wiki/Building

Key Functions
-------------

libfvde_encrypted_metadata_get_volume_master_key (libfvde/libfvde_encrypted_metadata.c)
