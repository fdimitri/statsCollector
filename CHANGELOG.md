#statsCollector CHANGELOG

##v0.0.1

### Done
* Initial basic functionality test through Linux sysfs
* Can gather statistics on network interfaces, kernel module, PCI ID
* Can parse PCIID information to display 'nice names'
* Will display if interface is part of a bridge and bridge IFName

### Todo
* Parse PCIID subsystem text
* Parse/Collect PCI subsystem data for more specific identification
* Parse USBID information
* Collect MAC address, speed, duplex, operstate, MTU, dormant mode, TXQLen
* Tie sub-interfaces to main interface (iflink)
* Collect ifalias
* Collect master/upper_* linkage
* Keep track of dev_id for 802.1q interfaces
* Error detection - begin/rescue catching
* Logging
* Break down to modules/classes
* Future: CPU load/PST/CST, Block devs, Filesystems, Bus Devices, VM guests, kernel, RAM, process tracking, system/platform (sensors)


