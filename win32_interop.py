from win32_definitions import *

class TCP4Connection(object):
    def __init__(self, local_addr, local_port, remote_addr,
                 remote_port, owning_pid):
        self.local_addr = local_addr
        self.local_port = local_port
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.owning_pid = owning_pid

    def __repr__(self):
        return ("Local Address: %s:%d\n" + \
                "Remote Address: %s:%d\n" + \
                "Owning Pid: %d") % (self.local_addr.decode('ascii'),
                                     self.local_port,
                                     self.remote_addr.decode('ascii'),
                                     self.remote_port,
                                     self.owning_pid)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
               self.local_addr == other.local_addr and \
               self.local_port == other.local_port and \
               self.remote_addr == other.remote_addr and \
               self.remote_port == other.remote_port and \
               self.owning_pid == other.owning_pid

    def __hash__(self):
        return hash((self.local_addr, self.local_port,
                     self.remote_addr, self.remote_port,
                     self.owning_pid))


class UDP4Connection(object):
    def __init__(self, local_addr, local_port, owning_pid):
        self.local_addr = local_addr
        self.local_port = local_port
        self.owning_pid = owning_pid

    def __repr__(self):
        return ("Local Address: %s:%d\n" + \
                "Owning Pid: %d") % (self.local_addr.decode('ascii'),
                                     self.local_port,
                                     self.owning_pid)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and \
               self.local_addr == other.local_addr and \
               self.local_port == other.local_port and \
               self.owning_pid == other.owning_pid

    def __hash__(self):
        return hash((self.local_addr, self.local_port,
                     self.owning_pid))


def find_pid(process_name: str):
    entry = PROCESSENTRY32W()
    entry.dwSize = sizeof(PROCESSENTRY32W)
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, None)
    condition = Process32First(snapshot, byref(entry))

    while condition == True:
        if process_name in string_at(entry.szExeFile):
            return entry.th32ProcessID
        condition = Process32Next(snapshot, byref(entry))
    CloseHandle(snapshot)

def get_tcp4_connections():
    ip_addr = in_addr()
    ptcp_table = cast(create_string_buffer(sizeof(MIB_TCPTABLE2_1)),
                      POINTER(MIB_TCPTABLE2_1))
    size = c_ulong(sizeof(MIB_TCPTABLE2_1))
    result = GetTcpTable2(ptcp_table, byref(size), TRUE)
    tcp4_connections = []

    # Get the real size of the table.
    if result == ERROR_INSUFFICIENT_BUFFER:
        ptcp_table = cast(create_string_buffer(size.value),
                          POINTER(MIB_TCPTABLE2_FACTORY(size.value)))

    result = GetTcpTable2(ptcp_table, byref(size), TRUE)
    if result == NO_ERROR:
        for i in range(0, ptcp_table[0].dwNumEntries):
            # Convert the local and remote addresses to human readable.
            ip_addr.S_un.S_addr = ptcp_table[0].table[i].dwLocalAddr
            local_addr = string_at(inet_nota(ip_addr))
            ip_addr.S_un.S_addr = ptcp_table[0].table[i].dwRemoteAddr
            remote_addr = string_at(inet_nota(ip_addr))
            tcp4_connection = TCP4Connection(
                local_addr=local_addr,
                remote_addr=remote_addr,
                local_port=ptcp_table[0].table[i].dwLocalPort,
                remote_port=ptcp_table[0].table[i].dwRemotePort,
                owning_pid=ptcp_table[0].table[i].dwOwningPid
            )

            tcp4_connections.append(tcp4_connection)
    return tcp4_connections

def get_udp4_connections():
    ip_addr = in_addr()
    pudp_table = cast(create_string_buffer(sizeof(MIB_UDPTABLE_OWNER_PID_1)),
                      POINTER(MIB_UDPTABLE_OWNER_PID_1))
    size = c_ulong(sizeof(MIB_UDPTABLE_OWNER_PID_1))
    result = GetExtendedUdpTable(pudp_table, byref(size), TRUE,
                                 AF_INET, UDP_TABLE_OWNER_PID, 0)
    udp4_connections = []

    # Get the real size of the table.
    if result == ERROR_INSUFFICIENT_BUFFER:
        pudp_table = cast(create_string_buffer(size.value),
                          POINTER(MIB_UDPTABLE_OWNER_PID_FACTORY(size.value)))

    result = GetExtendedUdpTable(pudp_table, byref(size), TRUE,
                                 AF_INET, UDP_TABLE_OWNER_PID, 0)
    if result == NO_ERROR:
        for i in range(0, pudp_table[0].dwNumEntries):
            # Convert the local and remote addresses to human readable.
            ip_addr.S_un.S_addr = pudp_table[0].table[i].dwLocalAddr
            local_addr = string_at(inet_nota(ip_addr))
            udp4_connection = UDP4Connection(
                local_addr=local_addr,
                local_port=pudp_table[0].table[i].dwLocalPort,
                owning_pid=pudp_table[0].table[i].dwOwningPid
            )

            udp4_connections.append(udp4_connection)
    return udp4_connections