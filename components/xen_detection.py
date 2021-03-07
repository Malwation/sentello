from winreg import *
import wmi


class xen_detection:

    def xen_process(self):
        try:
            c = wmi.WMI()
            processes_List = ["xenservice.exe"]
            detection = 0

            for process in c.win32_process():
                if process.Name in processes_List:
                    detection += 1
                    break
            if detection > 0:
                return True
            else:
                return False
        except:
            return False

    def xen_check_mac(self):
        try:
            c = wmi.WMI()
            detect = 0
            for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=1):
                if interface.MACAddress.find("08:16:3E") != -1:
                    return True
                else:
                    return False
        except:
            return False
