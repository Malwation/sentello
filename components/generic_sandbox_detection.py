import collections
import os
import sys
from datetime import datetime, timedelta
from winreg import *
import psutil
import pyautogui
import win32api
import win32process
import win32security
from hurry.filesize import size
import time
import wmi
import win32con
import win32service

"""
Tespit başarılı ise True  ELSE False

"""


class generic_sandbox_detection:

    def current_temperature_acpi_wmi(self):
        try:
            w = wmi.WMI(namespace="root\wmi")
            temperature_info = w.MSAcpi_ThermalZoneTemperature()[0]
            if temperature_info > 0:
                return False
            return True
        except:
            return True

    def accelerated_sleep(self):
        try:
            start = datetime.now()
            time.sleep(10)
            fark = datetime.now() - start
            if fark > timedelta(seconds=11):
                return True
            else:
                return False
        except:
            return False

    def cachememory_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_CacheMemory"
            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def cim_memory_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM CIM_Memory"

            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def cim_numericsensor_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM CIM_NumericSensor"

            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def cim_physicalconnector_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM CIM_PhysicalConnector"

            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def cim_sensor_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM CIM_Sensor"

            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def cim_slot_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM CIM_Slot"

            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def cim_temperaturesensor_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM CIM_TemperatureSensor"

            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def cim_voltagesensor_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM CIM_VoltageSensor"

            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def cpu_fan_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_Fan"

            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def disk_size_get_disk_free_space(self):
        try:

            c = wmi.WMI()
            wql = "SELECT * FROM Win32_LogicalDisk"
            for disk in c.query(wql):
                if int(size(int(disk.wmi_property("FreeSpace").value))[:-1]) < 80:
                    return True
                else:
                    return False
        except:
            return False

    def disk_size_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_LogicalDisk"
            for disk in c.query(wql):
                if int(size(int(disk.wmi_property("Size").value))[:-1]) < 40:
                    return True

            return False
        except:
            return False

    def known_file_names(self):
        nameList = ["sample.exe", "bot.exe", "sandbox.exe", "sandbox.exe", "malware.exe", "test.exe", "klavme.exe",
                    "myapp.exe", "testapp.exe", "infected.exe", "test.exe"]
        if sys.argv[0].split("/")[-1] in nameList:
            return True
        else:
            return False

    def known_username(self):
        usernameList = ["CurrentUser", "Sandbox", "Emily", "HAPUBWS", "Hong Lee", "IT-ADMIN", "Johnson", "Miller",
                        "milozs", "Peter Wilson", "timmy", "user", "sand box", "malware", "maltest", "test user",
                        "virus", "John Doe"]

        username = psutil.Process().username().split("\\")[1]

        if username in usernameList:
            return True
        else:
            return False

    def known_hostname(self):
        hostnameList = ["SANDBOX", "7SILVIA", "HANSPETER-PC", "JOHN-PC", "MUELLER-PC", "WIN7-TRAPS", "FORTINET",
                        "TEQUILABOOMBOOM"]

        username = psutil.Process().username().split("\\")[0]

        if username in hostnameList:
            return True
        else:
            return False

    def manufacturer_computer_system_wmi(self):
        try:
            manuList = ["VMWare", "Xen", "innotek GmbH", "QEMU"]

            c = wmi.WMI()
            wql = "SELECT * FROM Win32_ComputerSystem"

            for disk in c.query(wql):
                if disk.wmi_property("Manufacturer").value in manuList:
                    return True

            return False
        except:
            return False

    def mouse_movement(self):
        bef_x = pyautogui.position().x
        bef_y = pyautogui.position().y

        time.sleep(10)

        if not pyautogui.position().x != bef_x or not pyautogui.position().y != bef_y:
            return True
        else:
            return False

    def memoryarray_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_MemoryArray"

            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def memorydevice_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_MemoryDevice"

            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def memory_space(self):
        try:
            comp = wmi.WMI()

            for i in comp.Win32_ComputerSystem():
                if int(size(int(i.TotalPhysicalMemory))[:-1]) < 4:
                    return True
            return False
        except:
            return False

    def model_computer_system_wmi(self):
        try:
            modelList = ["VirtualBox", "HVM domU", "VMWare"]

            c = wmi.WMI()
            wql = "SELECT * FROM Win32_ComputerSystem"

            for disk in c.query(wql):
                if disk.wmi_property("Model").value in modelList:
                    return True

            return False
        except:
            return False

    def number_cores_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_Processor"
            for disk in c.query(wql):
                if disk.wmi_property("NumberOfCores").value < 2:
                    return True

            return False
        except:
            return False

    def number_of_processors(self):
        if os.cpu_count() < 2:
            return True
        else:
            return False

    def perfctrs_thermalzoneinfo_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_PerfFormattedData_Counters_ThermalZoneInformation"

            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def physicalmemory_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_PhysicalMemory"

            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def portconnector_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_PortConnector"

            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def process_id_processor_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_Processor"

            for disk in c.query(wql):
                if disk.wmi_property("ProcessorId").value is None:
                    return True
            return False
        except:
            return False

    def registry_disk_enum(self):
        aKeyList = ["System\CurrentControlSet\Enum\IDE",
                    "System\CurrentControlSet\Enum\SCSI"]
        blackList = ["qemu", "virtio", "vmware",
                     "vbox", "xen", "VMW", "Virtual"]
        detect = 0
        try:
            for key in aKeyList:
                aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
                aKey = OpenKey(aReg, key)
                try:
                    i = 0
                    while 1:
                        name, value, type = EnumValue(aKey, i)
                        if name in blackList or value in blackList:
                            detect += 1
                            break
                        i += 1
                except WindowsError:
                    pass
        except:
            pass

        if detect > 0:
            return True
        else:
            return False

    def registry_services_disk_enum(self):
        aKey = r"System\\CurrentControlSet\\Services\\Disk\\Enum"
        aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        aKey = OpenKey(aReg, aKey)

        blackList = ["qemu", "virtio", "vmware",
                     "vbox", "xen", "VMW", "Virtual"]
        detect = False

        try:
            i = 0
            while 1:
                name, value, type = EnumValue(aKey, i)
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

    def serial_number_bios_wmi(self):
        try:
            bios_list = ["VMWare", "0", "Xen", "Virtual", "A M I"]

            c = wmi.WMI()
            wql = "SELECT * FROM Win32_BIOS"

            for disk in c.query(wql):
                if disk.wmi_property("SerialNumber").value in bios_list:
                    return True
            return False
        except:
            return False

    def smbiosmemory_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_SMBIOSMemory"

            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def vm_driver_services(self):
        serviceList = ["VBoxWddm", "VBoxSF", "VBoxMouse", "VBoxGuest", "vmci", "vmhgfs", "vmmouse", "vmmemctl", "vmusb",
                       "vmusbmouse", "vmx_svga", "vmxnet", "vmx86"]
        resume = 0
        accessSCM = win32con.GENERIC_READ
        accessSrv = win32service.SC_MANAGER_ALL_ACCESS

        # Open Service Control Manager
        hscm = win32service.OpenSCManager(None, None, accessSCM)

        # Enumerate Service Control Manager DB
        typeFilter = win32service.SERVICE_WIN32
        stateFilter = win32service.SERVICE_STATE_ALL

        statuses = win32service.EnumServicesStatus(
            hscm, typeFilter, stateFilter)

        for (short_name, desc, status) in statuses:
            if short_name in serviceList:
                return True
        return False

    def voltageprobe_wmi(self):
        try:
            c = wmi.WMI()
            wql = "SELECT * FROM Win32_VoltageProbe"
            if len(c.query(wql)) <= 0:
                return True
            else:
                return False
        except:
            return False

    def loaded_dlls(self):
        blacklist = ["avghookx.dll", "avghooka.dll", "snxhk.dll", "sbiedll.dll", "dbghelp.dll", "api_log.dll",
                     "dir_watch.dll", "pstorec.dll", "vmcheck.dll", "wpespy.dll", "cmdvrt64.dll", "cmdvrt32.dll"]

        for i in self.__list_processes():
            if i.modules != []:
                for j in i.modules:
                    if str(j).split("\\")[-1] in blacklist:
                        return True

        return False

    def __adjust_privilege(self, name, attr=win32security.SE_PRIVILEGE_ENABLED):
        if isinstance(name, str):
            state = (win32security.LookupPrivilegeValue(None, name), attr)
        else:
            state = name
        hToken = win32security.OpenProcessToken(win32process.GetCurrentProcess(),
                                                win32security.TOKEN_ALL_ACCESS)
        return win32security.AdjustTokenPrivileges(hToken, False, [state])

    def __get_process_modules(self, hProcess):
        imagepath = win32process.GetModuleFileNameEx(hProcess, None)
        imagepath_upper = imagepath.upper()
        modules = []
        for hModule in win32process.EnumProcessModulesEx(hProcess,
                                                         win32process.LIST_MODULES_ALL):
            modulepath = win32process.GetModuleFileNameEx(hProcess, hModule)
            if modulepath.upper() != imagepath_upper:
                modules.append(modulepath)
        return imagepath, sorted(modules)

    def __list_processes(self):
        Process = collections.namedtuple('Process', 'name path pid modules')
        prev_state = self.__adjust_privilege(win32security.SE_DEBUG_NAME)
        try:
            for pid in win32process.EnumProcesses():
                hProcess = None
                path = ''
                modules = []
                if pid == 0:
                    name = 'System Idle Process'
                elif pid == 4:
                    name = 'System'
                else:
                    try:
                        hProcess = win32api.OpenProcess(
                            0x1000 |
                            win32con.PROCESS_VM_READ,
                            False, pid)
                    except win32api.error:
                        try:
                            hProcess = win32api.OpenProcess(
                                0x1000,
                                False, pid)
                        except win32api.error as e:
                            pass
                    if hProcess:
                        try:
                            path, modules = self.__get_process_modules(
                                hProcess)
                        except win32process.error:
                            pass
                    name = os.path.basename(path)
                yield Process(name, path, pid, modules)
        finally:
            if prev_state:
                self.__adjust_privilege(prev_state[0])
