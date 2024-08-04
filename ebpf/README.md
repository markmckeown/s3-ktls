Monitor HTTPS connection - detects connect, sends and shutdown.
Uses TC and tracepoints

```
sudo ./https_monitoring.py -i eno1
```


Monitor incoming packets via XDP arriving on port 443

```
sudo ./https_incoming_counter.py 
```


Monitor io_uring events:

```
sudo ./trace_io_uring.py 
```


Trace tcp IPv4 connects:

```
sudo ./tcpv4connect.py
```



 

