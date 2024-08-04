#!/usr/bin/python3

from bcc import BPF
import pyroute2
import socket
import struct
import argparse


verbose_states = {
    1: "Connection connect",
    2: "Connection send",
    3: "Connection destroyed",
}


def get_verbose_message(state):
    if state not in verbose_states:
        return ""

    return verbose_states[state]


def ip_to_network_address(ip):
    return struct.unpack("I", socket.inet_aton(ip))[0]


def network_address_to_ip(ip):
    return socket.inet_ntop(socket.AF_INET, struct.pack("I", ip))


def create_tc(interface):
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    try:
        idx = ipdb.interfaces[interface].index
    except:
        print(f"[-] {interface} interface not found")
        return False, False, False

    try:
        # deleting if exists from previous run
        ip.tc("del", "clsact", idx)
    except:
        pass
    ip.tc("add", "clsact", idx)
    return ip, ipdb, idx


def parse_verbose_event(cpu, data, size):
    event = bpf["verbose_events"].event(data)
    src_ip = network_address_to_ip(event.src_ip)
    dst_ip = network_address_to_ip(event.dst_ip)
    verbose_message = get_verbose_message(event.state)
    print(f"{event.pid}: {event.comm.decode()} - {src_ip}:{event.src_port} -> {dst_ip}:{event.dst_port} - {verbose_message} {event.len}")


parser = argparse.ArgumentParser(description="Monitor outgoing connections to port 443")
parser.add_argument("-i", "--interface", help="Network interface name to monitor traffic on", required=True, type=str)
args = parser.parse_args()
print(f"[+] Monitoring {args.interface} interface")


with open("https_monitoring.c", "r") as f:
    bpf_text = f.read()


ip, ipdb, idx = create_tc(args.interface)
if not ip:
    exit(-1)

bpf = BPF(text=bpf_text)

# loading kprobe
bpf.attach_kprobe(event="tcp_connect", fn_name="trace_connect_entry")

# loading TC
fn = bpf.load_func("handle_egress", BPF.SCHED_CLS)


ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff3", classid=1, direct_action=True)
bpf["verbose_events"].open_perf_buffer(parse_verbose_event)


print("[+] Monitoring started\n")
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break

ip.tc("del", "clsact", idx)
ipdb.release()

