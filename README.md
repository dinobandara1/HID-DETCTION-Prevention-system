# HID-Detection &-Prevention-system
This script is a Python program that implements a HID (Human Interface Device) defender. It includes various modules and libraries such as win32.win32file, wmi, pyclamd, tkinter, pywinusb.hid, hvac, subprocess, win32api, and ctypes 
The script defines several functions and classes to perform the following tasks:
Interact with USB devices:
Get the serial number and drive letter of a USB device.
Check if a device is authorized or blacklisted.
Add or remove devices from the authorized or blacklist.
Block or unblock USB ports.
Scan for malware:
Start the ClamAV daemon if not running.
Scan a USB device for malware using ClamAV.
Add infected devices to the blacklist.
Authenticate users and devices:
Authenticate the user with a password.
Authenticate a device and add it to the authorized devices.
GUI (Graphical User Interface):
Create a GUI using tkinter to start and stop monitoring devices.
Show the blacklist of devices.
Allow the removal of devices from the blacklist.
