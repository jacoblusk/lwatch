from win32_interop import get_tcp4_connections, find_pid, \
                          get_udp4_connections
from time import sleep
from sys import argv, stderr
from os.path import basename
from signal import signal, SIGINT, SIGTERM

def handle_signal(signum, frame):
    print("exit")
    exit()

signal(SIGINT, handle_signal)
signal(SIGTERM, handle_signal)

def main():
    if len(argv) < 2:
        print("usage: %s program_name" % basename(__file__), file=stderr)
        return 1

    program_name = argv[1]
    unique_tcp_connections = set()
    unique_udp_connections = set()

    while True:
        program_pid = find_pid(program_name.encode('ascii'))
        tcp4_connections = get_tcp4_connections()
        program_tcp4_connections = [conn for conn in tcp4_connections \
                                    if conn.owning_pid == program_pid]

        udp4_connections = get_udp4_connections()
        program_udp4_connections = [conn for conn in udp4_connections \
                            if conn.owning_pid == program_pid]

        for x in program_tcp4_connections:
            if x not in unique_tcp_connections:
                unique_tcp_connections.add(x)
                print(x)

        for x in program_udp4_connections:
            if x not in unique_udp_connections:
                unique_udp_connections.add(x)
                print(x)
        sleep(2)

if __name__ == "__main__":
    error_code = main()
    exit(error_code)
