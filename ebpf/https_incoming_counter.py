#!/usr/bin/python3

from bcc import BPF
from bcc.utils import printb
from time import sleep

device = "eno1" 
b = BPF(src_file="https_incoming_counter.c") 
fn = b.load_func("https_incoming_counter", BPF.XDP) 
b.attach_xdp(device, fn, 0) 

try:
    dist = b.get_table("counter") 
    while True:
        sleep(2)
        for k, v in dist.items(): 
            print("SRC_PORT : %10d, COUNT : %10d" % (k.value, v.value)) 

except KeyboardInterrupt: 
    print("Exiting")

b.remove_xdp(device, 0) 
