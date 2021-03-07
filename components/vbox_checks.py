from winreg import *
import platform
import os
from uuid import getnode as get_mac
import psutil
import wmi


class vbox_checks:
    def vbox_reg_key_value(self):
        try:
            aKey = [r"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
                    r"HARDWARE\\Description\\System",
                    r"HARDWARE\\Description\\System",
                    r"HARDWARE\\Description\\System"]
            aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
            detect = False
            for f in aKey:
                akey = OpenKey(aReg, f)

                blackList = ["VBOX", "VIRTUALBOX", "06/23/99"]
                try:
                    i = 0
                    while 1:
                        name, value, type = EnumValue(akey, i)
                        if name in blackList or value in blackList:
                            detect = True
                            break
                        i += 1
                except WindowsError:
                    pass

            if detect:
                return True
            else:
                return False
        except:
            return False

    def vbox_dir(self):
        try:
            pat = "oracle\\virtualbox guest additions\\"

            if platform.machine().endswith('64'):
                ev = os.getenv('ProgramW6432')
                if os.path.exists(ev + "\\oracle\\virtualbox guest additions\\"):
                    return True
                else:
                    return False
            else:
                ev = os.getenv("ProgramFiles(x86)")
                if os.path.exists(ev + "\\oracle\\virtualbox guest additions\\"):
                    return True
                else:
                    return False
        except:
            return False

    def vbox_files(self):
        try:
            szPaths = [
                "System32\\drivers\\VBoxMouse.sys",
                "System32\\drivers\\VBoxGuest.sys",
                "System32\\drivers\\VBoxSF.sys",
                "System32\\drivers\\VBoxVideo.sys",
                "System32\\vboxdisp.dll",
                "System32\\vboxhook.dll",
                "System32\\vboxmrxnp.dll",
                "System32\\vboxogl.dll",
                "System32\\vboxoglarrayspu.dll",
                "System32\\vboxoglcrutil.dll",
                "System32\\vboxoglerrorspu.dll",
                "System32\\vboxoglfeedbackspu.dll",
                "System32\\vboxoglpackspu.dll",
                "System32\\vboxoglpassthroughspu.dll",
                "System32\\vboxservice.exe",
                "System32\\vboxtray.exe",
                "System32\\VBoxControl.exe"]
            dr = False
            for szpath in szPaths:
                if os.path.isfile("C:\\" + szpath):
                    dr = True

            if dr:
                return True
            else:
                return False
        except:
            return False

    def vbox_reg_keys(self):
        try:
            aKeys = [
                "HARDWARE\\ACPI\\DSDT\\VBOX__",
                "HARDWARE\\ACPI\\FADT\\VBOX__",
                "HARDWARE\\ACPI\\RSDT\\VBOX__",
                "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
                "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
                "SYSTEM\\ControlSet001\\Services\\VBoxMouse",
                "SYSTEM\\ControlSet001\\Services\\VBoxService",
                "SYSTEM\\ControlSet001\\Services\\VBoxSF",
                "SYSTEM\\ControlSet001\\Services\\VBoxVideo"
            ]

            detect = False
            for f in aKeys:

                try:
                    reg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
                    akey = OpenKey(aReg, f)
                    print("found")
                    detect = True

                except:
                    pass
            if detect:
                return True
            else:
                return False
        except:
            return False

    def vbox_check_mac(self):
        try:
            blackmac = "080027"
            mac = str(get_mac())
            dr = False
            if mac[:6] == blackmac:
                dr = True

            if dr:
                return True
            else:
                return False
        except:
            return False

    def hybrid_analysis_mac_detect(self):
        try:
            blackmac = "0A0027"
            mac = str(get_mac())
            dr = False
            if mac[:6] == blackmac:
                dr = True

            if dr:
                return True
            else:
                return False
        except:
            return False

    def vbox_processes(self):
        try:
            blacklist = ["vboxservice.exe", "vboxtray.exe"]
            dr = False
            for proc in psutil.process_iter():
                try:
                    processName = proc.name()
                    if processName == blacklist[0] or processName == blacklist[1]:
                        dr = True

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            if dr == True:
                return True
            else:
                return False
        except:
            return False

    def vbox_pnpentity_pcideviceid_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_PnPEntity"

            for disk in c.query(wql):
                if disk.wmi_property("DeviceId").value == "PCI\\VEN_80EE&DEV_CAFE":
                    return True
                return False
        except:
            return False

    def vbox_pnpentity_controllers_wmi(self):
        try:
            blacklist = ["82801FB", "82441FX", "82371SB", "OpenHCD"]
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_PnPEntity"

            for disk in c.query(wql):
                if disk.wmi_property("Name").value in blacklist:
                    return True
                return False
        except:
            return False

    def vbox_pnpentity_vboxname_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_PnPDevice"
            dr = False
            try:
                for disk in c.query(wql):
                    if disk.wmi_property("Name").value == "VBOX":
                        dr = True

                if dr == True:
                    return True
                else:
                    return False
            except:
                return False
        except:
            return False

    def vbox_bus_wmi(self):
        try:
            c = wmi.WMI()
            blacklist = ["ACPIBus_BUS_0", "PCI_BUS_0", "PNP_BUS_0"]
            wql = "SELECT * FROM Win32_Bus"
            dr = False
            try:
                for disk in c.query(wql):
                    if disk.wmi_property("Name").value in blacklist:
                        dr = True

                if dr == True:
                    return True
                else:
                    return False
            except:
                return False
        except:
            return False

    def vbox_baseboard_wmi(self):
        try:
            c = wmi.WMI()
            blacklist = ["VirtualBox"]
            wql = "SELECT * FROM Win32_BaseBoard"
            dr = False
            try:
                for disk in c.query(wql):
                    if disk.wmi_property("Product").value in blacklist:
                        dr = True

                if dr == True:
                    return True
                else:
                    return False
            except:
                return False
        except:
            return False

    def vbox_mac_wmi(self):
        try:
            c = wmi.WMI()
            blacklist = ["08:00:27"]
            wql = "SELECT * FROM Win32_NetworkAdapterConfiguration"
            dr = False
            try:
                for disk in c.query(wql):
                    st = str(disk.wmi_property("MACAddress").value)
                    if st[:8] in blacklist:
                        dr = True

                if dr == True:
                    return True
                else:
                    return False
            except:
                return False
        except:
            return False

    def vbox_firmware_SMBIOS(self):
        try:
            c = wmi.WMI()
            smbios = c.Win32_BIOS()[0].SMBIOSBIOSVersion
            if smbios.find("VirtualBox") != -1 or smbios.find("vbox") != -1 or smbios.find("VBOX") != -1:
                return True
            else:
                return False
        except:
            return False

    def vbox_firmware_ACPI(self):
        try:
            c = wmi.WMI()
            smbios = c.Win32_BIOS()[0].Version
            if smbios.find("VirtualBox") != -1 or smbios.find("vbox") != -1 or smbios.find("VBOX") != -1:
                return True
            else:
                return False
        except:
            return False
