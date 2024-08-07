import angr as ag
import networkx as nx
import logging as lg
import math as mt
import time as tm
import yara as yr
import os
import colorama as cr
from colorama import Fore as F, Style as S
from datetime import datetime as dt
cr.init(autoreset=True)
lg.getLogger('angr').setLevel(lg.CRITICAL)
lg.getLogger('cle').setLevel(lg.CRITICAL)
lg.getLogger('pyvex').setLevel(lg.CRITICAL)
MIN = 1000
MAX = 100000
SF = [
    "LoadLibrary", "GetProcAddress", "VirtualAlloc", "VirtualProtect",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "ShellExecute", "WinExec", "CreateProcess",
    "NtCreateThreadEx", "NtWriteVirtualMemory", "NtReadVirtualMemory",
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtUnmapViewOfSection",
    "NtMapViewOfSection", "SetWindowsHookEx", "UnhookWindowsHookEx",
    "SetWindowsHook", "GetModuleHandle", "GetModuleFileName", "CreateFileMapping",
    "MapViewOfFile", "UnmapViewOfFile", "LoadLibraryEx", "GetCurrentProcessId",
    "GetCurrentThreadId", "GetThreadContext", "SetThreadContext", "DebugActiveProcess",
    "DebugActiveProcessStop", "TerminateProcess", "SuspendThread", "ResumeThread",
    "AdjustTokenPrivileges", "OpenProcessToken", "DuplicateTokenEx",
    "RegOpenKeyEx", "RegCreateKeyEx", "RegSetValueEx", "RegDeleteKeyEx",
    "RegDeleteValue", "CreatePipe",
    "CreateRemoteThreadEx", "SetFileAttributes", "GetFileAttributes", "CreateFile",
    "CloseHandle", "VirtualFree", "VirtualQuery", "GetLastError"
]
ADF = [
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "NtSetInformationThread",
    "DebugActiveProcess", "DebugActiveProcessStop", "OutputDebugString",
    "GetThreadContext", "SetThreadContext", "VirtualQuery", "VirtualQueryEx",
    "Wow64GetThreadContext", "Wow64SetThreadContext", "NtQuerySystemInformation",
    "NtQueryObject", "NtQueryInformationThread", "NtQueryInformationProcess",
    "NtSetInformationProcess", "NtSetInformationThread", "NtCreateThreadEx",
    "NtOpenThread", "NtOpenProcess", "NtSuspendProcess", "NtResumeProcess",
    "NtTerminateProcess", "NtWaitForSingleObject", "NtWaitForMultipleObjects",
    "NtAlertResumeThread", "NtAlertThread", "ZwQueryInformationProcess",
    "ZwSetInformationProcess", "ZwQueryInformationThread", "ZwSetInformationThread",
    "ZwCreateThreadEx", "ZwOpenThread", "ZwOpenProcess", "ZwSuspendProcess",
    "ZwResumeProcess", "ZwTerminateProcess", "ZwWaitForSingleObject",
    "ZwWaitForMultipleObjects", "ZwAlertResumeThread", "ZwAlertThread"
]
AVF = [
    "VboxService", "VBoxTray", "VBoxGuest", "VMwareService",
    "VMwareTray", "VMwareUser", "vmtoolsd", "vmware-vmx",
    "vmmem", "vmmemctl", "VBoxClient", "VBoxService",
    "VBoxControl", "VBoxHeadless", "VBoxSVC", "VMMR0", "VMMR0.r0",
    "VBoxManage", "VBoxStartup", "VBoxTray", "VMwareToolbox",
    "VMwareView", "VMwareAuthd", "VMwareUser", "VMwareToolboxCmd"
]
AAF = [
    "GetTickCount", "QueryPerformanceCounter", "timeGetTime", "NtDelayExecution",
    "ZwSetInformationThread", "SetUnhandledExceptionFilter",
    "Sleep", "WaitForSingleObject", "WaitForMultipleObjects", "WaitForInputIdle",
    "SetTimer", "KillTimer", "QueryPerformanceFrequency", "GetSystemTimeAsFileTime",
    "GetSystemTime", "GetLocalTime", "NtWaitForSingleObject", "NtWaitForMultipleObjects",
    "ZwWaitForSingleObject", "ZwWaitForMultipleObjects", "ZwDelayExecution",
    "ZwSetTimer", "ZwCancelTimer", "ZwQuerySystemInformation", "NtQuerySystemInformation",
    "NtDelayExecution", "SetThreadPriority", "GetThreadPriority", "SetPriorityClass",
    "GetPriorityClass", "GetThreadTimes", "SetThreadTimes", "NtSetInformationProcess",
    "NtQueryInformationProcess", "NtSetEvent", "NtResetEvent", "NtPulseEvent"
]
def cc():
    os.system('cls' if os.name == 'nt' else 'clear')
def cC(g):
    ne = g.graph.number_of_edges()
    nn = g.graph.number_of_nodes()
    nc = nx.number_weakly_connected_components(g.graph)
    return ne - nn + 2 * nc
def nCS(s, mi=MIN, ma=MAX):
    ns = (s - mi) / (ma - mi) * 100
    return ns
def cNS(ns):
    if ns >= 70:
        return "Very High Obfuscation"
    elif ns >= 50:
        return "High Obfuscation"
    elif ns >= 25:
        return "Moderate Obfuscation"
    elif ns >= 10:
        return "Light Obfuscation"
    elif ns >= 5:
        return "Very Light Obfuscation"
    else:
        return "Not Obfuscated"
def cE(d):
    if not d:
        return 0
    e = 0
    dl = len(d)
    fr = {b: d.count(b) for b in set(d)}
    for b in fr:
        px = fr[b] / dl
        e -= px * mt.log2(px)
    return e
def cEnt(e):
    if e >= 7:
        return "Highly Packed"
    elif e >= 6.1:
        return "Packed"
    else:
        return "Not Packed"
def iF(p):
    g = p.analyses.CFGFast(normalize=True)
    fs = []
    for fa, f in g.kb.functions.items():
        if f.name not in fs:
            fs.append(f.name)
    return fs
def fSF(fs, sl):
    s = []
    for f in fs:
        if any(sf in f for sf in sl):
            s.append(f)
    return s
def pS(t, c, rc=F.LIGHTWHITE_EX):
    print(f"\n{F.WHITE}{t}")
    if c:
        for i in c:
            print(f"{rc}- {i}")
    else:
        print(f"{rc}None.")
def uP(m):
    ts = dt.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"[{ts}] {m}")
    tm.sleep(1)
def yS(fp):
    rd = './yara'
    rf = [os.path.join(rd, f) for f in os.listdir(rd) if f.endswith('.yar')]
    r = yr.compile(filepaths={f"r_{i}": rf for i, rf in enumerate(rf)})
    m = r.match(fp)
    return [mr.rule for mr in m]
def aP(fp):
    print(f"\nAnalyzing file: {F.LIGHTRED_EX}{fp}")
    uP("Analyzing Control Flow")
    st = tm.time()
    p = ag.Project(fp, auto_load_libs=False)
    g = p.analyses.CFGFast(show_progressbar=True, normalize=True, force_complete_scan=False, data_references=False, collect_data_references=False)
    et = tm.time() - st
    if et < 1:
        tm.sleep(1 - et)
    uP("Calculating Obfuscation")
    st = tm.time()
    cs = cC(g)
    ns = nCS(cs)
    cl = cNS(ns)
    et = tm.time() - st
    if et < 1:
        tm.sleep(1 - et)
    uP("Calculating Entropy")
    st = tm.time()
    with open(fp, 'rb') as f:
        fd = f.read()
    e = cE(fd)
    pv = cEnt(e)
    et = tm.time() - st
    if et < 1:
        tm.sleep(1 - et)
    uP("Identifying Suspicious Functions")
    st = tm.time()
    fs = iF(p)
    sf = fSF(fs, SF)
    adf = fSF(fs, ADF)
    avf = fSF(fs, AVF)
    aaf = fSF(fs, AAF)
    et = tm.time() - st
    if et < 1:
        tm.sleep(1 - et)
    uP("Performing YARA Scan")
    st = tm.time()
    ym = yS(fp)
    et = tm.time() - st
    if et < 1:
        tm.sleep(1 - et)
    cc()
    print(f"\n{F.LIGHTRED_EX}{fp}\n")
    print(f"{F.WHITE}ROS: {F.LIGHTWHITE_EX}{cs}")
    print(f"{F.WHITE}NOS: {F.LIGHTWHITE_EX}{ns:.2f}")
    print(f"{F.WHITE}Entropy: {F.LIGHTWHITE_EX}{e:.2f}")
    pS("Obfuscation Verdict:", [cl])
    pS("Packer Verdict:", [pv])
    pS("Suspicious Functions:", sf)
    pS("Anti-Debugging Functions:", adf)
    pS("Anti-VM Functions:", avf)
    pS("Anti-Analysis Functions:", aaf)
    if ym:
        pS("YARA Matches:", ym, rc=F.LIGHTRED_EX)
    else:
        pS("YARA Matches:", ym)
def main():
    st = "Welcome to Introspekt v1.0"
    cc()
    print(st.center(os.get_terminal_size().columns))
    tm.sleep(2)
    cc()
    fp = input("File to scan: ")
    cc()
    aP(fp)
    input("\nPress Enter to close.")
if __name__ == "__main__":
    main()
