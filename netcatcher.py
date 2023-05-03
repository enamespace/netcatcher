from bcc import BPF
import time

from prettytable import PrettyTable
# reload(sys)
# sys.setdefaultencoding('utf8')





def pid_to_name(pid):
    try:
        comm = open("/proc/%s/comm" % pid, "r").read().rstrip()[:30]
        return comm
    except IOError:
        return str(pid)

bpf = BPF(src_file="netcatcher.c")

bpf.attach_kprobe(event="sock_recvmsg", fn_name="net_catcher_prog")

exited = False
while not exited:
    try:
        
        table = PrettyTable(['PID','CMD','TCP','UDP'])
        for k, v in bpf["catcher"].items():
            table.add_row([k.value,pid_to_name(k.value),v.recv_total_tcp, v.recv_total_udp])
        print(table)
        print('#'*10)
        time.sleep(1)
    except KeyboardInterrupt:
        exited = True
    
