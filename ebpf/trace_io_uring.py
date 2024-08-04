#!/usr/bin/python3

from bcc import BPF

# load BPF program
b = BPF(text="""
TRACEPOINT_PROBE(io_uring, io_uring_submit_sqe) {
    bpf_trace_printk("%d\\n", args->user_data);
    return 0;
};
""")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "IO_URING user_data"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt: 
        print("Exiting")
        exit(0)
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
