from ctypes import windll, CDLL
from ctypes import POINTER, Structure, sizeof, byref, cast, Union
from ctypes import c_ulong, c_int, c_char, c_ubyte, c_ushort, c_char_p, \
                   c_void_p, c_wchar, c_wchar_p, c_long
from ctypes import create_string_buffer, string_at, memset, \
                   create_unicode_buffer, wstring_at


TRUE = 1
FALSE = 0
MAX_PATH = 260

TH32CS_SNAPPROCESS = 0x00000002

ERROR_INSUFFICIENT_BUFFER = 122
ERROR_INVALID_PARAMETER = 87
ERROR_NOT_SUPPORTED = 50
INVALID_HANDLE_VALUE = -1
NO_ERROR = 0

UDP_TABLE_OWNER_PID = 1
AF_INET = 2
AF_INET6 = 10

class S_un_b(Structure):
    _fields_ = [
        ("s_b1", c_ubyte),
        ("s_b2", c_ubyte),
        ("s_b3", c_ubyte),
        ("s_b4", c_ubyte)
    ]


class S_un_w(Structure):
    _fields_ = [
        ("s_w1", c_ushort),
        ("s_w2", c_ushort)
    ]


class S_un(Union):
    _fields_ = [
        ("S_un_b", S_un_b),
        ("S_un_w", S_un_w),
        ("S_addr", c_ulong)
    ]


class in_addr(Structure):
    _fields_ = [
        ("S_un", S_un)
    ]


class MIB_TCPROW2(Structure):
    _fields_ = [
        ("dwState", c_ulong),
        ("dwLocalAddr", c_ulong),
        ("dwLocalPort", c_ulong),
        ("dwRemoteAddr", c_ulong),
        ("dwRemotePort", c_ulong),
        ("dwOwningPid", c_ulong),
        ("dwOffloadState", c_int)
    ]

class MIB_UDPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwLocalAddr", c_ulong),
        ("dwLocalPort", c_ulong),
        ("dwOwningPid", c_ulong)
    ]

def MIB_UDPTABLE_OWNER_PID_FACTORY(size: int):
    class MIB_UDPTABLE_OWNER_PID(Structure):
        _fields_ = [
            ("dwNumEntries", c_ulong),
            ("table", MIB_UDPROW_OWNER_PID * size)
        ]
    return MIB_UDPTABLE_OWNER_PID

def MIB_TCPTABLE2_FACTORY(size: int):
    class MIB_TCPTABLE2(Structure):
        _fields_ = [
            ("dwNumEntries", c_ulong),
            ("table", MIB_TCPROW2 * size)
        ]
    return MIB_TCPTABLE2


class PROCESSENTRY32W(Structure):
    _fields_ = [
        ("dwSize", c_ulong),
        ("cntUsage", c_ulong),
        ("th32ProcessID", c_ulong),
        ("th32DefaultHeapID", POINTER(c_ulong)),
        ("th32ModuleId", c_ulong),
        ("cntThreads", c_ulong),
        ("th32ParentProcessID", c_ulong),
        ("pcPriClassBase" , c_long),
        ("dwFlags", c_ulong),
        ("szExeFile", c_wchar * MAX_PATH)
    ]


libc = CDLL("msvcrt")
libc.wcslen.argtypes = [c_wchar_p]

inet_nota = windll.ws2_32.inet_ntoa
inet_nota.argtypes = [in_addr]
inet_nota.restype = c_char_p

MIB_TCPTABLE2_1 = MIB_TCPTABLE2_FACTORY(1)
MIB_UDPTABLE_OWNER_PID_1 = MIB_UDPTABLE_OWNER_PID_FACTORY(1)

GetTcpTable2 = windll.iphlpapi.GetTcpTable2
GetTcpTable2.argtypes = [c_void_p, POINTER(c_ulong), c_int]
GetTcpTable2.restype = c_ulong

GetExtendedUdpTable = windll.iphlpapi.GetExtendedUdpTable
GetExtendedUdpTable.argtypes = [c_void_p, POINTER(c_ulong), c_int, c_ulong, c_int, c_ulong]
GetExtendedUdpTable.restype = c_ulong

CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.argtypes = [c_ulong, POINTER(c_ulong)]
CreateToolhelp32Snapshot.restype = c_ulong

Process32First = windll.kernel32.Process32First
Process32First.argtypes = [c_ulong, POINTER(PROCESSENTRY32W)]
Process32First.restype = c_int

Process32Next = windll.kernel32.Process32Next
Process32Next.argtypes = [c_ulong, POINTER(PROCESSENTRY32W)]
Process32Next.restype = c_int

OpenProcess = windll.kernel32.OpenProcess
OpenProcess.argtypes = [c_ulong, c_ubyte, c_ulong]
OpenProcess.restype = c_ulong

GetModuleBaseName = windll.psapi.GetModuleBaseNameW
GetModuleBaseName.argtypes = [c_ulong, c_ulong, c_wchar_p, c_ulong]
GetModuleBaseName.restype = c_ulong

GetProcessImageFileName = windll.psapi.GetProcessImageFileNameW
GetProcessImageFileName.argtypes = [c_ulong, c_wchar_p, c_ulong]
GetProcessImageFileName.restype = c_ulong

CloseHandle = windll.kernel32.CloseHandle
CloseHandle.argtypes = [c_ulong]
CloseHandle.restype = c_ubyte