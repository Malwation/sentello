from winreg import *
import wmi


class qemu_detection:

    def qemu_reg_key_value(self):
        try:
            regList = [
                ["HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
                    "Identifier", "QEMU"],
                ["HARDWARE\Description\System", "SystemBiosVersion", "QEMU"]]
            detection = 0
            try:
                for row in regList:
                    reg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
                    key = OpenKey(reg, row[0])
                    try:
                        i = 0
                        while True:
                            name, value, type = EnumValue(key, i)
                            if name == row[2] or value == row[2]:
                                detection += 1
                                break
                            i += 1
                    except WindowsError:
                        pass
            except:
                pass
            if detection > 0:
                return True
            else:
                return False
        except:
            return False

    def qemu_processes(self):
        try:
            c = wmi.WMI()
            processes_List = ["qemu-ga.exe"]
            detection = 0
            for row in processes_List:
                for process in c.win32_process():
                    if process.Name == row:
                        detection += 1
            if detection > 0:
                return True
            else:
                return False
        except:
            return False

    def qemu_firmware_SMBIOS(self):
        try:
            c = wmi.WMI()
            smbios = c.Win32_BIOS()[0].SMBIOSBIOSVersion
            if smbios.find("qemu") != -1 or smbios.find("QEMU") != -1:
                return True
            else:
                return False
        except:
            return False

    def qemu_firmware_ACPI(self):
        try:
            c = wmi.WMI()
            smbios = c.Win32_BIOS()[0].Version
            if smbios.find("BOCHS") != -1 or smbios.find("BXPC") != -1:
                return True
            else:
                return False
        except:
            return False
