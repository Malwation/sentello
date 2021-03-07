import wmi


class paralles_detection:
    def paralles_process(self):
        try:
            c = wmi.WMI()
            processes_List = ["prlcc_.exe", "prl_tools.exe"]
            detection = 0
            for row in processes_List:
                for process in c.win32_process():
                    if process.Name in processes_List:
                        detection += 1
            if detection > 0:
                return True
            else:
                return False
        except:
            return False

    def paralles_check_mac(self):
        try:
            c = wmi.WMI()
            for interface in c.Win32_NetworkAdapterConfiguration(IPEnabled=1):
                if interface.MACAddress.find("00:1C:42") != -1:
                    return True
            return False
        except:
            return False
