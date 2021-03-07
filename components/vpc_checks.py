import psutil
from winreg import *


class vpc_checks:

    def virtual_pc_process(self):
        blackList = ["VMSrvc.exe", "VMUSrvc.exe"]

        for proc in psutil.process_iter():
            try:
                if proc.name() in blackList:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        return False

    def virtual_pc_reg_keys(self):
        try:
            akey = "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"
            aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
            _ = OpenKey(aReg, akey)
            return True
        except:
            return False
