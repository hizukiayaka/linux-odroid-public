# Vanilla Linux 4.6.y for the Odroid-X2/U2/U3

This is a [linux-4.6.y](https://git.kernel.org/cgit/linux/kernel/git/stable/linux-stable.git/log/?h=linux-4.6.y) tree with some modifications to make it work on a Hardkernel Odroid-X2 developer board. The U2/U3 boards should work as well, but are neither owned nor tested by me.


TODOs:

   - work on Mali DVFS code
   - remove more of the always-on properties of the various regulators
   - modify refclk code in usb3503 (make it more generic)

EXTERNAL TODOs:

   - DRM runtime PM currently not functional when IOMMU is used
