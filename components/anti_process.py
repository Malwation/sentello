import wmi


class anti_process:
    def analysis_tools_process(self):
        try:
            c = wmi.WMI()
            processes_List = ["ollydbg.exe", "ProcessHacker.exe", "tcpview.exe", "autoruns.exe",
                              "autorunsc.exe", "filemon.exe", "procmon.exe", "regmon.exe", "procexp.exe", "idaq.exe",
                              "idaq64.exe", "ImmunityDebugger.exe", "Wireshark.exe", "dumpcap.exe", "HookExplorer.exe", "ImportREC.exe", "PETools.exe", "LordPE.exe", "SysInspector.exe", "proc_analyzer.exe", "sysAnalyzer.exe",
                              "sniff_hit.exe",
                              "windbg.exe", "joeboxcontrol.exe", "joeboxserver.exe", "joeboxserver.exe",
                              "ResourceHacker.exe", "x32dbg.exe", "x64dbg.exe",
                              "Fiddler.exe", "httpdebugger.exe"]
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
