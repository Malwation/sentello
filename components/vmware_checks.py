import os
from winreg import *
import platform
import psutil
from getmac import get_mac_address
import wmi

"""
Tespit başarılı ise True  ELSE False

"""


class vmware_checks:

    def vmware_reg_key_value(self):
        aKeylist = [
            ["HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier",
             "VMWARE"],
            ["HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier",
             "VMWARE"],
            ["HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier",
             "VMWARE"],
            ["SYSTEM\\ControlSet001\\Control\\SystemInformation",
                "SystemManufacturer", "VMWARE"],
            ["SYSTEM\\ControlSet001\\Control\\SystemInformation",
                "SystemManufacturer", "VMWARE"]
        ]
        aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        detect = False
        for keylist in aKeylist:

            try:
                aKey = OpenKey(aReg, keylist[0])
                i = 0
                while 1:
                    name, value, type = EnumValue(aKey, i)
                    if name == keylist[1] and value == keylist[2]:
                        detect = True
                    i += 1
            except WindowsError:
                pass

        if detect:
            return True
        else:
            return False

    def vmware_reg_keys(self):

        try:
            akey = "SOFTWARE\\VMware, Inc.\\VMware Tools"
            aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
            _ = OpenKey(aReg, akey)
            return True
        except:
            return False

    def vmware_files(self):
        fileList = [
            "System32\\drivers\\vmnet.sys",
            "System32\\drivers\\vmmouse.sys",
            "System32\\drivers\\vmusb.sys",
            "System32\\drivers\\vm3dmp.sys",
            "System32\\drivers\\vmci.sys",
            "System32\\drivers\\vmhgfs.sys",
            "System32\\drivers\\vmmemctl.sys",
            "System32\\drivers\\vmx86.sys",
            "System32\\drivers\\vmrawdsk.sys",
            "System32\\drivers\\vmusbmouse.sys",
            "System32\\drivers\\vmkdb.sys",
            "System32\\drivers\\vmnetuserif.sys",
            "System32\\drivers\\vmnetadapter.sys"
        ]
        windows = os.getenv("windir")
        for i in fileList:
            if os.path.exists(windows + os.sep + i):
                return True
        return False

    def vmware_mac(self):
        macList = ["00:05:69", "00:0c:29", "00:1C:14", "00:50:56"]
        mymac = get_mac_address()
        for i in macList:
            if mymac.startswith(i):
                return True
        return False

    def vmware_adapter_name(self):
        addrs = psutil.net_if_addrs()
        for i in addrs.keys():
            if str(i).__contains__("VMware"):
                return True
        return False

    def vmware_firmware_SMBIOS(self):
        try:
            c = wmi.WMI()
            smbios = c.Win32_BIOS()[0].SMBIOSBIOSVersion
            if smbios.find("vmware") != -1 or smbios.find("VMware") != -1:
                return True
            else:
                return False
        except:
            return False

    def vmware_firmware_ACPI(self):
        try:
            c = wmi.WMI()
            smbios = c.Win32_BIOS()[0].Version
            if smbios.find("BOCHS") != -1 or smbios.find("BXPC") != -1:
                return True
            else:
                return False
        except:
            return False

    def vmware_dir(self):
        if platform.machine().endswith('64'):
            ev = os.getenv('ProgramW6432')
            if os.path.exists(ev + "\\VMWare\\"):
                return True
            else:
                return False
        else:
            ev = os.getenv("ProgramFiles(x86)")
            if os.path.exists(ev + "\\VMWare\\"):
                return True
            else:
                return False
