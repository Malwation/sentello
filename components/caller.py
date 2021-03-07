import json
from termcolor import *
from components.anti_process import anti_process
from components.paralles_detection import paralles_detection
from components.generic_sandbox_detection import generic_sandbox_detection
from components.qemu_detection import qemu_detection
from components.vbox_checks import vbox_checks
from components.vmware_checks import vmware_checks
from components.vpc_checks import vpc_checks
from components.xen_detection import xen_detection
from components.wine_detection import wine_detection
from ctypes import *
import os


class caller:

    def _logger(self, category, desc, result):
        if result == True:
            result = "Success"
            cprint(f"[+]{desc:<70}{result:>25}", 'white')

        else:
            result = "Fail"
            cprint(f"[+]{desc:<70}{result:>25}", 'red')

        with open("output.json", "r") as file:
            readed = json.loads(file.read())
        template = {
            "description": desc,
            "result": result,
        }
        logs = {}
        check = False
        for i in readed["categories"]:
            if i["category_name"] == category:
                logs = i["functions"]
                logs.append(template)
                i["functions"] = logs
                with open("output.json", "w+") as file:
                    file.write(json.dumps(readed))
                check = True
        if check == False:
            general_tmp = {
                "category_name": category,
                "functions": [template]
            }
            readed["categories"].append(general_tmp)
            with open("output.json", "w+") as file:
                file.write(json.dumps(readed))

    def __init__(self, arg_main):

        lib = cdll.LoadLibrary(os.path.join(
            os.path.dirname(__file__), "vm-detector.dll"))
        with open("output.json", "w") as file:
            file.write('{"categories":[]}')

        if arg_main["debug"] == True:  # Debugger Detection
            _category = "Debugger Detection"
            test = "[*]--" + _category + " Started--[*]"
            cprint(f"{test:^95}", 'blue')

            self._logger(_category, "Checking PEB.BeingDebugged",
                         lib.IsDebuggerPresentPEB())

            self._logger(_category, "Checking CheckRemoteDebuggerPresent API",
                         lib.CheckRemoteDebuggerPresentAPI())

            self._logger(_category, "Checking CloseHandle with an invalide handle",
                         lib.CloseHandle_InvalideHandle())

            self._logger(_category, "Checking Hardware Breakpoints",
                         lib.HardwareBreakpoints())

            self._logger(_category, "Checking IsDebuggerPresent API",
                         lib.IsDebuggerPresentAPI())

            self._logger(_category, "Checking Low Fragmentation Heap",
                         lib.LowFragmentationHeap())

            self._logger(_category, "Checking Memory Breakpoints PAGE GUARD",
                         lib.MemoryBreakpoints_PageGuard())

            self._logger(
                _category, "Checking for API hooks outside module bounds", lib.ModuleBoundsHookCheck())

            self._logger(_category, "Checking PEB.NtGlobalFlag",
                         lib.NtGlobalFlag())

            # lib.NtQueryInformationProcess_ProcessDebugFlags()              #Getting OSError Exception
            # lib.NtQueryInformationProcess_ProcessDebugObject()             #Getting OSError Exception
            # lib.NtQueryInformationProcess_ProcessDebugPort()               #Getting OSError Exception
            # lib.NtQueryObject_ObjectAllTypesInformation()                  #Getting OSError Exception
            # lib.NtQuerySystemInformation_SystemKernelDebuggerInformation() #Getting OSError Exception
            # lib.NtSetInformationThread_ThreadHideFromDebugger()            #Getting OSError Exception
            # lib.NtYieldExecutionAPI()

            self._logger(_category, "Checking OutputDebugString",
                         lib.OutputDebugStringAPI())

            self._logger(_category, "Checking for page exception breakpoints ",
                         lib.PageExceptionBreakpointCheck())

            # lib.IsParentExplorerExe()                                      #Getting OSError Exception

            self._logger(_category, "Checking ProcessHeap.Flags",
                         lib.HeapFlags())

            self._logger(
                _category, "Checking ProcessHeap.ForceFlags", lib.HeapForceFlags())

            self._logger(
                _category, "Checking if process is in a job", lib.ProcessJob())

            self._logger(_category, "Checking SeDebugPrivilege",
                         lib.CanOpenCsrss())

            self._logger(_category, "Checking CloseHandle protected handle trick",
                         lib.SetHandleInformatiom_ProtectedHandle())

            self._logger(_category, "Checking SharedUserData->KdDebuggerEnabled",
                         lib.SharedUserData_KernelDebugger())

            self._logger(_category, "Checking Software Breakpoints",
                         lib.SoftwareBreakpoints())

            self._logger(_category, "Checking trap flag",  lib.TrapFlag())

            # lib.UnhandledExcepFilterTest()                                 #Getting OSError Exception

            self._logger(_category, "Checking VirtualAlloc write watch (IsDebuggerPresent) ",
                         lib.VirtualAlloc_WriteWatch_IsDebuggerPresent())

            self._logger(_category, "Checking VirtualAlloc write watch (code write) ",
                         lib.VirtualAlloc_WriteWatch_CodeWrite())

            self._logger(_category, "Checking VirtualAlloc write watch (buffer only) ",
                         lib.VirtualAlloc_WriteWatch_BufferOnly())

            self._logger(_category, "Checking VirtualAlloc write watch (API calls)",
                         lib.VirtualAlloc_WriteWatch_APICalls())

            self._logger(_category, "Checking WudfIsUserDebuggerPresent API",
                         lib.WUDF_IsUserDebuggerPresent())

            self._logger(_category, "Checking WudfIsKernelDebuggerPresent API",
                         lib.WUDF_IsKernelDebuggerPresent())

            self._logger(_category, "Checking WudfIsAnyDebuggerPresent API",
                         lib.WUDF_IsAnyDebuggerPresent())

        if arg_main["tls"] == True:  # TLS Callbacks
            _category = "TLS Callbacks"
            test = "[*]--" + _category + " Started--[*]"
            cprint(f"{test:^95}", 'blue')

            self._logger(_category, "TLS process attach callback",
                         lib.TLSCallbackProcess())

            self._logger(_category, "TLS thread attach callback",
                         lib.TLSCallbackThread())

        if arg_main["injection"] == True:  # DLL Injection Detection
            _category = "DLL Injection Detection"
            test = "[*]--" + _category + " Started--[*]"
            cprint(f"{test:^95}", 'blue')

            self._logger(_category, "Walking process memory with GetModuleInformation ",
                         lib.ScanForModules_MemoryWalk_GMI())

            self._logger(_category, "Walking process memory for hidden modules ",
                         lib.ScanForModules_MemoryWalk_Hidden())

            self._logger(
                _category, "Enumerating modules with EnumProcessModulesEx [32-bit]", lib.ScanForModules_EnumProcessModulesEx_32bit())

            self._logger(
                _category, "Enumerating modules with EnumProcessModulesEx [64-bit]", lib.ScanForModules_EnumProcessModulesEx_64bit())

            self._logger(
                _category, "Enumerating modules with EnumProcessModulesEx [ALL] ", lib.ScanForModules_EnumProcessModulesEx_All())

            self._logger(_category, "Enumerating modules with ToolHelp32 ",
                         lib.ScanForModules_ToolHelp32())

            self._logger(_category, "Enumerating the process LDR via LdrEnumerateLoadedModules",
                         lib.ScanForModules_LdrEnumerateLoadedModules())

            # lib.ScanForModules_LDR_Direct()                                #Getting OSError Exception

        if arg_main["vbox"] == True:
            test = "[*]--VBOX Check Started--[*]"
            cprint(f"{test:^95}", 'blue')
            self._call_vbox_checks()

        if arg_main["vmware"] == True:
            test = "[*]--Vmware Check Started--[*]"
            cprint(f"{test:^95}", 'blue')
            self._call_vmware_checks()

        if arg_main["vpc"] == True:
            test = "[*]--Virtual PC Check Started--[*]"
            cprint(f"{test:^95}", 'blue')
            self._call_vpc_checks()

        if arg_main["qemu"] == True:
            test = "[*]--Qemu Check Started--[*]"
            cprint(f"{test:^95}", 'blue')
            self._call_qemu_detection()

        if arg_main["xen"] == True:
            test = "[*]--Xen Check Started--[*]"
            cprint(f"{test:^95}", 'blue')
            self._call_xen_detection()

        if arg_main["wine"] == True:
            test = "[*]--Wine Check Started--[*]"
            cprint(f"{test:^95}", 'blue')
            self._call_wine_detection()

        if arg_main["parallels"] == True:
            test = "[*]--Parallels Check Started--[*]"
            cprint(f"{test:^95}", 'blue')
            self._call_paralles_detection()

        if arg_main["code"] == True:
            _category = "Code İnjection"
            test = "[*]--" + _category + " Started--[*]"
            cprint(f"{test:^95}", 'blue')

            self._logger(_category, "Create RemoteThread Injection",
                         lib.CreateRemoteThread_Injection())

            self._logger(_category, "Get SetThreadContext Injection",
                         lib.GetSetThreadContext_Injection())

            self._logger(_category, "NtCreateThreadEx Injection",
                         lib.NtCreateThreadEx_Injection())

            self._logger(_category, "RtlCreateUserThread Injection",
                         lib.RtlCreateUserThread_Injection())

            self._logger(_category, "SetWindowsHooksEx Injection",
                         lib.SetWindowsHooksEx_Injection())

        if arg_main["timing"] == True:
            _category = "Timing"
            test = "[*]--" + _category + " Started--[*]"
            time = "[!]--Time-based attacks can take a long time--[!]"
            cprint(f"{test:^95}", 'blue')
            cprint(f"{time:^95}", 'blue')

            self._logger(_category, "WaitForSingleObject",
                         lib.timing_WaitForSingleObject(5))

            self._logger(_category, "timeSetEvent", lib.timing_timeSetEvent())

            self._logger(_category, "SetTimer", lib.timing_SetTimer(5))

            self._logger(_category, "NtDelayexecution",
                         lib.timing_NtDelayexecution(5))

            self._logger(_category, "IcmpSendEcho", lib.timing_IcmpSendEcho(5))

            self._logger(_category, "CreateWaitableTimer",
                         lib.timing_CreateWaitableTimer(5))

            self._logger(_category, "CreateTimerQueueTimer",
                         lib.timing_CreateTimerQueueTimer(5))

        if arg_main["dumping"] == True:
            _category = "Anti Dumping"
            test = "[*]--" + _category + " Started--[*]"
            cprint(f"{test:^95}", 'blue')

            self._logger(_category, "Size Of Image", lib.SizeOfImage())

            self._logger(_category, "Erase PE Header From Memory",
                         lib.ErasePEHeaderFromMemory())

        if arg_main["tools"] == True:
            test = "[*]--Analysis-tools Check Started--[*]"
            cprint(f"{test:^95}", 'blue')
            self._call_anti_process()

        if arg_main["disasm"] == True:
            _category = "Anti Disassm"
            test = "[*]--" + _category + " Started--[*]"
            cprint(f"{test:^95}", 'blue')

            self._logger(_category, "Anti Disassm Return Pointer Abuse",
                         lib.AntiDisassmReturnPointerAbuse())

            self._logger(_category, "Anti Disassm Impossible Diasassm",
                         lib.AntiDisassmImpossibleDiasassm())

            self._logger(_category, "Anti Disassm Function Pointer",
                         lib.AntiDisassmFunctionPointer())

            self._logger(_category, "Anti Disassm Constant Condition",
                         lib.AntiDisassmConstantCondition())

            self._logger(_category, "Anti Disassm Asm Jmp Same Target",
                         lib.AntiDisassmAsmJmpSameTarget())

        if arg_main["sandbox"] == True:
            test = "[*]--Generic Sandbox Check Started--[*]"
            cprint(f"{test:^95}", 'blue')
            self._call_generic_sandbox()

    def _call_wine_detection(self):  # Wine Detection
        _category = "Wine Detection"

        self._logger(_category, "Wine Reg Keys",
                     wine_detection.wine_reg_keys(self))

    def _call_xen_detection(self):  # Xen Detection
        _category = "Xen Detection"

        self._logger(_category, "XEN Process", xen_detection.xen_process(self))

        self._logger(_category, "XEN check mac",
                     xen_detection.xen_check_mac(self))

    def _call_vpc_checks(self):  # Virtual PC Detection
        _category = "Virtual PC Detection"

        self._logger(_category, "Virtual PC Process",
                     vpc_checks.virtual_pc_process(self))

        self._logger(_category, "Virtual Pc Reg Keys",
                     vpc_checks.virtual_pc_reg_keys(self))

    def _call_vmware_checks(self):  # VMWare Detection
        _category = "VMWare Detection"

        self._logger(_category, "VMware Reg key values",
                     vmware_checks.vmware_reg_key_value(self))

        self._logger(_category, "VMware reg keys",
                     vmware_checks.vmware_reg_keys(self))

        self._logger(_category, "VMware Files",
                     vmware_checks.vmware_files(self))

        self._logger(_category, "VMware Mac", vmware_checks.vmware_mac(self))

        self._logger(_category, "VMware Adapter Name",
                     vmware_checks.vmware_adapter_name(self))

        self._logger(_category, "VMware Firmware SMBIOS",
                     vmware_checks.vmware_firmware_SMBIOS(self))

        self._logger(_category, "VMware Firmware ACPI",
                     vmware_checks.vmware_firmware_ACPI(self))

        self._logger(_category, "VMware Directory",
                     vmware_checks.vmware_dir(self))

    def _call_vbox_checks(self):  # VirtualBox Detection
        _category = "VirtualBox Detection"

        self._logger(_category, "VBOX reg key values",
                     vbox_checks.vbox_reg_key_value(self))

        self._logger(_category, "VBOX directories", vbox_checks.vbox_dir(self))

        self._logger(_category, "VBOX files", vbox_checks.vbox_files(self))

        self._logger(_category, "VBOX registry keys",
                     vbox_checks.vbox_reg_keys(self))

        self._logger(_category, "VBOX MAC check",
                     vbox_checks.vbox_check_mac(self))

        self._logger(_category,  "Hybrid analysis mac detect",
                     vbox_checks.hybrid_analysis_mac_detect(self))

        self._logger(_category, "VBOX Processes",
                     vbox_checks.vbox_processes(self))

        self._logger(_category, "Checking Win32_PnPDevice DeviceId from WMI for VBox PCI device",
                     vbox_checks.vbox_pnpentity_pcideviceid_wmi(self))

        self._logger(_category, "Checking Win32_PnPDevice Name from WMI for VBox controller hardware ",
                     vbox_checks.vbox_pnpentity_controllers_wmi(self))

        self._logger(_category, "Checking Win32_PnPDevice Name from WMI for VBOX names",
                     vbox_checks.vbox_pnpentity_vboxname_wmi(self))

        self._logger(_category, "Checking Win32_Bus from WMI",
                     vbox_checks.vbox_bus_wmi(self))

        self._logger(_category, "Checking Win32_BaseBoard from WMI",
                     vbox_checks.vbox_baseboard_wmi(self))

        self._logger(_category, "Checking MAC address from WMI",
                     vbox_checks.vbox_mac_wmi(self))

        self._logger(_category, "Checking SMBIOS firmware",
                     vbox_checks.vbox_firmware_SMBIOS(self))

        self._logger(_category, "Checking ACPI tables",
                     vbox_checks.vbox_firmware_ACPI(self))

    def _call_qemu_detection(self):  # QEMU Detection
        _category = "QEMU Detection"

        self._logger(_category, "QEMU registry key values",
                     qemu_detection.qemu_reg_key_value(self))

        self._logger(_category, "QEMU Processes",
                     qemu_detection.qemu_processes(self))

        self._logger(_category, "QEMU Firmware SMBIOS",
                     qemu_detection.qemu_firmware_SMBIOS(self))

        self._logger(_category, "QEMU Firmware ACPI",
                     qemu_detection.qemu_firmware_ACPI(self))

    def _call_anti_process(self):  # Analysis-tools
        _category = "Analysis-tools"

        self._logger(_category, "Checking analysis tools process",
                     anti_process.analysis_tools_process(self))

    def _call_paralles_detection(self):  # Paralles Detection
        _category = "Paralles Detection"

        self._logger(_category, "Checking paralles process",
                     paralles_detection.paralles_process(self))

        self._logger(_category, "Checking paralles check mac",
                     paralles_detection.paralles_check_mac(self))

    def _call_generic_sandbox(self):  # Generic Sandboxe/VM Detection
        _category = "Generic Sandboxe/VM Detection"

        self._logger(_category, "Current temperature acpi wmi",
                     generic_sandbox_detection.current_temperature_acpi_wmi(self))

        self._logger(_category, "Accelerated sleep",
                     generic_sandbox_detection.accelerated_sleep(self))

        self._logger(_category, "Cachememory wmi",
                     generic_sandbox_detection.cachememory_wmi(self))

        self._logger(_category, "Cim memory wmi",
                     generic_sandbox_detection.cim_memory_wmi(self))

        self._logger(_category, "Cim numericsensor wmi",
                     generic_sandbox_detection.cim_numericsensor_wmi(self))

        self._logger(_category, "Cim physicalconnector wmi",
                     generic_sandbox_detection.cim_physicalconnector_wmi(self))

        self._logger(_category, "Cim sensor wmi",
                     generic_sandbox_detection.cim_sensor_wmi(self))

        self._logger(_category, "Cim slot wmi",
                     generic_sandbox_detection.cim_slot_wmi(self))

        self._logger(_category, "Cim temperature sensor wmi",
                     generic_sandbox_detection.cim_temperaturesensor_wmi(self))

        self._logger(_category, "Cim voltage sensor wmi",
                     generic_sandbox_detection.cim_voltagesensor_wmi(self))

        self._logger(_category, "Cpu fan wmi",
                     generic_sandbox_detection.cpu_fan_wmi(self))

        self._logger(_category, "Disk size get disk free space",
                     generic_sandbox_detection.disk_size_get_disk_free_space(self))

        self._logger(_category, "Disk size wmi",
                     generic_sandbox_detection.disk_size_wmi(self))

        self._logger(_category, "Known file names",
                     generic_sandbox_detection.known_file_names(self))

        self._logger(_category, "Known usernames",
                     generic_sandbox_detection.known_username(self))

        self._logger(_category, "Known hostnames",
                     generic_sandbox_detection.known_hostname(self))

        self._logger(_category, "Manufacturer computer system wmi",
                     generic_sandbox_detection.manufacturer_computer_system_wmi(self))

        self._logger(_category, "Mouse movement",
                     generic_sandbox_detection.mouse_movement(self))

        self._logger(_category, "Memory array wmi",
                     generic_sandbox_detection.memoryarray_wmi(self))

        self._logger(_category, "Memory device wmi",
                     generic_sandbox_detection.memorydevice_wmi(self))

        self._logger(_category, "Memory space",
                     generic_sandbox_detection.memory_space(self))

        self._logger(_category, "Model computer system wmi",
                     generic_sandbox_detection.model_computer_system_wmi(self))

        self._logger(_category, "Number cores wmi",
                     generic_sandbox_detection.number_cores_wmi(self))

        self._logger(_category, "Number of processors",
                     generic_sandbox_detection.number_of_processors(self))

        self._logger(_category, "Perfctrs Thermal zone info wmi",
                     generic_sandbox_detection.perfctrs_thermalzoneinfo_wmi(self))

        self._logger(_category, "Physical Memory wmi",
                     generic_sandbox_detection.physicalmemory_wmi(self))

        self._logger(_category, "Port connector wmi",
                     generic_sandbox_detection.portconnector_wmi(self))

        self._logger(_category, "Process id processor wmi",
                     generic_sandbox_detection.process_id_processor_wmi(self))

        self._logger(_category, "Registry disk enum",
                     generic_sandbox_detection.registry_disk_enum(self))

        self._logger(_category, "Registry services disk enum",
                     generic_sandbox_detection.registry_services_disk_enum(self))

        self._logger(_category, "Serial number bios wmi",
                     generic_sandbox_detection.serial_number_bios_wmi(self))

        self._logger(_category, "SMBIOS memory wmi",
                     generic_sandbox_detection.smbiosmemory_wmi(self))

        self._logger(_category, "Vm Driver Services",
                     generic_sandbox_detection.vm_driver_services(self))

        self._logger(_category, "Voltage probe wmi",
                     generic_sandbox_detection.voltageprobe_wmi(self))
