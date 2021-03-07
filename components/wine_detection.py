from winreg import *
import wmi


class wine_detection:
    def wine_reg_keys(self):
        detect = True
        try:
            aKey = r"SOFTWARE\\Wine"
            aReg = ConnectRegistry(None, HKEY_CURRENT_USER)
            aKey = OpenKey(aReg, aKey)
        except WindowsError:
            detect = False

        return detect
