from win32.win32file import DeviceIoControl
import wmi
import pyclamd
import time
import logging
import tkinter as tk
import tkinter.simpledialog as simpledialog
import pywinusb.hid as hid
import tkinter.messagebox as messagebox
import wmi
import hvac
import subprocess
import pywinusb.hid as hid
import win32file
import win32api
import ctypes
from tkinter import messagebox

clamd = pyclamd.ClamdNetworkSocket(host='localhost', port=3310)
logger = logging.getLogger(__name__)
logging.basicConfig(filename='hid_defender.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
client = hvac.Client(url='http://localhost:8200')


def get_serial_number(device):
    c = wmi.WMI()
    usb_device = c.Win32_USBControllerDevice(DeviceID=device.deviceID).FirstInstance
    serial_number = None
    if usb_device is not None:
        try:
            serial_number = usb_device.GetDependent().SerialNumber
        except wmi.x_wmi as e:
            logger.exception(f"Error getting serial number: {e}")
    return serial_number

def get_drive_letter(serial_number):
    drive_list = win32api.GetLogicalDriveStrings()
    drives = drive_list.split('\000')[:-1]
    for drive in drives:
        drive_type = win32file.GetDriveType(drive)
        if drive_type == win32file.DRIVE_REMOVABLE:
            volume_serial_number = win32file.GetVolumeInformation(drive)[1]
            if volume_serial_number == serial_number:
                return drive
    return None

def get_blacklist():
    try:
        blacklist_from_vault = client.secrets.kv.v2.read_secret_version(path='secrets/blacklist')['data']['data']['devices']
    except Exception as e:
        logger.exception(f"Error reading blacklist from Vault: {e}")
        return set()
    return set(blacklist_from_vault)

def add_to_blacklist(device_serial):
    blacklist = get_blacklist()
    blacklist.add(device_serial)
    try:
        client.secrets.kv.v2.create_or_update_secret(path='secret/blacklist', secret={'devices': list(blacklist)})
    except Exception as e:
        logger.exception(f"Error adding device to blacklist: {e}")

def remove_from_blacklist(device_serial):
    blacklist = get_blacklist()
    if device_serial in blacklist:
        blacklist.remove(device_serial)
        try:
            client.secrets.kv.v2.create_or_update_secret(path='secret/blacklist', secret={'devices': list(blacklist)})
        except Exception as e:
            logger.exception(f"Error removing device from blacklist: {e}")

def get_authorized_devices():
    try:
        authorized_devices_from_vault = client.secrets.kv.v2.read_secret_version(path='secret/authorized')['data']['data']['devices']
    except Exception as e:
        logger.exception(f"Error reading authorized devices from Vault: {e}")
        return set()

    return set(authorized_devices_from_vault)

def authorize_device(device):
    device_serial = device.serial_number
    authorized_devices = get_authorized_devices()
    authorized_devices.add(device_serial)
    try:
        client.secrets.kv.v2.create_or_update_secret(path='secrets/authorized', secret={'devices': list(authorized_devices)})
        logger.info(f"Device {device_serial} authorized successfully")
    except Exception as e:
        logger.exception(f"Error authorizing device: {e}")

def add_to_authorized_devices(device_serial):
    authorized_devices = get_authorized_devices()
    authorized_devices.add(device_serial)
    try:
        client.secrets.kv.v2.create_or_update_secret(path='secrets/authorized', secret={'devices': list(authorized_devices)})
    except Exception as e:
        logger.exception(f"Error adding device to authorized devices: {e}")

def remove_from_authorized_devices(device_serial):
    authorized_devices = get_authorized_devices()
    if device_serial in authorized_devices:
        authorized_devices.remove(device_serial)
        try:
            client.secrets.kv.v2.create_or_update_secret(path='secrets/authorized', secret={'devices': list(authorized_devices)})
        except Exception as e:
            logger.exception(f"Error removing device from authorized devices: {e}")

def is_authorized(device_id):
    authorized_devices = get_authorized_devices()
    if device_id in authorized_devices:
        return True
    else:
        return False

def is_blacklisted(device_id):
    blacklist = get_blacklist()
    if device_id in blacklist:
        return True
    else:
        return False

def block_usb_ports():
    try:
        subprocess.run(["powershell", "-Command", "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 4"], check=True)
    except subprocess.CalledProcessError as e:
        logger.exception(f"Error blocking USB ports: {e}")

def unblock_usb_ports():
    try:
        subprocess.run(["powershell", "-Command", "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name 'Start' -Value 3"], check=True)
    except subprocess.CalledProcessError as e:
        logger.exception(f"Error unblocking USB ports: {e}")

def start_clamd():
    clamd = pyclamd.ClamdNetworkSocket(host='localhost', port=3310)
    if not clamd.ping():
        logger.info("ClamAV daemon not running, starting it now...")
        subprocess.run(["clamd.exe", "--foreground"], check=True, cwd="C:\\Program Files\\ClamAV")
        time.sleep(120)
        clamd = pyclamd.ClamdNetworkSocket(host='localhost', port=3310)
        if not clamd.ping():
            logger.error("Failed to start ClamAV daemon")
            return False
    return True

def has_malware(device):
    try:
        serial_number = get_serial_number(device)
        if not serial_number:
            return False

        drive_letter = get_drive_letter(serial_number)
        if not drive_letter:
            return True

        if not start_clamd():
            return True

        clamd = pyclamd.ClamdNetworkSocket(host='localhost', port=3310)
        with open(drive_letter, "rb") as drive:
            scan_result = clamd.scan_file(drive_letter, byte=True)
            if scan_result:
                logger.info(f"Malware detected on {drive_letter}: {scan_result}")
                return True
            else:
                logger.info(f"No malware detected on {drive_letter}")
                return False

    except pyclamd.ConnectionError as e:
        logger.exception(f"Error connecting to ClamAV: {e}")
        return True

    except pyclamd.ScanError as e:
        logger.exception(f"Error scanning for malware: {e}")
        return True

    except Exception as e:
        logger.exception(f"Error checking for malware: {e}")
        return True
    
def authenticate():
    try:
        root = tk.Tk()
        root.withdraw()
        client = hvac.Client(url='http://localhost:8200')
        client.token = "hvs.j0eYVclx5zaRYGVURFiEuUOH"
        password_secret_version_response = client.secrets.kv.v2.read_secret_version(path='secret/hid_defender_password')
        password = password_secret_version_response['data']['data']['password']
        user_password = simpledialog.askstring("HID Defender", "Enter password:", show='*')
        if user_password == password:
            return True
        else:
            return False
    except Exception as e:
        print(f"Error authenticating user: {e}")
        messagebox.showerror("HID Defender", f"Error authenticating user: {e}")
        return False
        
def authenticate_device(device_id):
    add_to_authorized_devices(device_id)

def handle_device_connection(device_id):
    if is_authorized(device_id):
        if is_blacklisted(device_id):
            block_usb_ports()
            messagebox.showerror("HID Defender", "Device is blacklisted. Please remove the device.")
            time.sleep(20)
            authenticate_device(device_id)
            unblock_usb_ports()
        else:
            if has_malware(device_id):
                add_to_blacklist(device_id)
                block_usb_ports()
                messagebox.showerror("HID Defender", "Device has malware and has been blacklisted. Please remove the device.")
                time.sleep(20)
                authenticate_device(device_id)
                unblock_usb_ports()
            else:
                unblock_usb_ports()
    else:
        authenticate_device(device_id)
        unblock_usb_ports()
    
class HIDdefendGUI:
    def __init__(self, master):
        self.master = master
        master.title("HID Defender")

        menu_bar = tk.Menu(master)
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Exit", command=master.quit)
        master.config(menu=menu_bar)

        start_button = tk.Button(master, text="Start Monitoring", command=self.start_monitoring)
        start_button.pack()
        stop_button = tk.Button(master, text="Stop Monitoring", command=self.stop_monitoring)
        stop_button.pack()
        blacklist_button = tk.Button(master, text="Show Blacklist", command=self.show_blacklist_gui)
        blacklist_button.pack()

        self.status_bar = tk.Label(master, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.devices = []

    def start_monitoring(self):
        self.status_bar.config(text="Monitoring devices")
        def on_hid_event(data):
            self.on_hid_event(data)

        filter = hid.HidDeviceFilter()
        filter.add_vendor_id(0x1234)  
        devices = filter.get_devices()

        for device in devices:
            device.open()
            device.set_raw_data_handler(on_hid_event)
            self.devices.append(device)

    def stop_monitoring(self):
        try:
            self.stop_hid_monitor()  
            messagebox.showinfo("HID Defender", "Monitoring stopped")
            self.status_bar.config(text="Monitoring stopped")
        except Exception as e:
            print(f"Error stopping monitoring: {e}")
            messagebox.showerror("HID Defender", f"Error stopping monitoring: {e}")

    def stop_hid_monitor(self):  
        pass

    def show_blacklist_gui(self):
        blacklist_window = tk.Toplevel(self.master)
        blacklist_window.title("Blacklist")
        blacklist_listbox = tk.Listbox(blacklist_window)
        blacklist_listbox.pack(fill=tk.BOTH, expand=True)
        for vendor_id in get_blacklist():
            blacklist_listbox.insert(tk.END, vendor_id)

    def on_hid_event(self, data):
        vendor_id = data[0]
        product_id = data[1]
        if is_authorized(vendor_id):
            if is_blacklisted(vendor_id):
                block_usb_ports()
                messagebox.showerror("HID Defender", "Device is blacklisted. Please remove the device.")
                time.sleep(20)
                authenticate_device(vendor_id)
                unblock_usb_ports()
            else:
                if has_malware(data):
                    add_to_blacklist(vendor_id)
                    block_usb_ports()
                    messagebox.showerror("HID Defender", "Device has malware and has been blacklisted. Please remove the device.")
                    time.sleep(20)
                    authenticate_device(vendor_id)
                    unblock_usb_ports()
                else:
                    authenticate_device()
                    unblock_usb_ports()
        else:
            block_usb_ports()
            messagebox.showerror("HID Defender", "Device is not authorized. Please remove the device.")
            time.sleep(20)
            authenticate_device(vendor_id)
            unblock_usb_ports()

    filter = hid.HidDeviceFilter(vendor_id=0x1234) 
    devices = filter.get_devices()

    for device in devices:
        device.open()
        device.set_raw_data_handler(on_hid_event)
        device.set_raw_data_buffer(64)
    def show_blacklist_gui(self):
        try:
            if authenticate():
                blacklist_window = tk.Toplevel(self.master)
                blacklist_window.title("Blacklist")

                search_frame = tk.Frame(blacklist_window)
                search_label = tk.Label(search_frame, text="Search:")
                search_label.pack(side=tk.LEFT)
                search_entry = tk.Entry(search_frame)
                search_entry.pack(side=tk.LEFT)
                search_button = tk.Button(search_frame, text="Search", command=lambda: self.update_blacklist_listbox(blacklist_listbox, search_entry.get(), filter_var.get()))
                search_button.pack(side=tk.LEFT)
                search_frame.pack()

                filter_frame = tk.Frame(blacklist_window)
                filter_label = tk.Label(filter_frame, text="Filter:")
                filter_label.pack(side=tk.LEFT)
                filter_var = tk.StringVar(value="All")
                filter_options = ["All", "Keyboards", "Mice", "Other"]
                for option in filter_options:
                    filter_radio = tk.Radiobutton(filter_frame, text=option, variable=filter_var, value=option, command=lambda: self.update_blacklist_listbox(blacklist_listbox, search_entry.get(), filter_var.get()))
                    filter_radio.pack(side=tk.LEFT)
                filter_frame.pack()

                blacklist_listbox = tk.Listbox(blacklist_window)
                self.update_blacklist_listbox(blacklist_listbox, "", "All")
                blacklist_listbox.pack()

                remove_button = tk.Button(blacklist_window, text="Remove", command=lambda: self.remove_device_from_blacklist(blacklist_listbox))
                remove_button.pack()
            else:
                messagebox.showerror("HID Defender", "Authentication failed")
        except Exception as e:
            print(f"Error showing blacklist: {e}")
            messagebox.showerror("HID Defender", f"Error showing blacklist: {e}")

    def update_blacklist_listbox(self, blacklist_listbox, search_text, filter_option):
        blacklist = get_blacklist()
        filtered_blacklist = []
        for device in blacklist:
            if search_text.lower() in device.lower():
                if filter_option == "All":
                    filtered_blacklist.append(device)
                elif filter_option == "Keyboards" and "keyboard" in device.lower():
                    filtered_blacklist.append(device)
                elif filter_option == "Mice" and "mouse" in device.lower():
                    filtered_blacklist.append(device)
                elif filter_option == "Other" and "keyboard" not in device.lower() and "mouse" not in device.lower():
                    filtered_blacklist.append(device)
        blacklist_listbox.delete(0, tk.END)
        for device in filtered_blacklist:
            blacklist_listbox.insert(tk.END, device)

def remove_device_from_blacklist(self, blacklist_listbox):
        try:
            selected_device = blacklist_listbox.get(blacklist_listbox.curselection())
            remove_device_from_blacklist(selected_device)
            blacklist_listbox.delete(blacklist_listbox.curselection())
            messagebox.showinfo("HID Defender", f"{selected_device} removed from blacklist")
        except Exception as e:
            print(f"Error removing device from blacklist: {e}")
            messagebox.showerror("HID Defender", f"Error removing device from blacklist: {e}")

root = tk.Tk()
gui = HIDdefendGUI(root)
root.mainloop()
