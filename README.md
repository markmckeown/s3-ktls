# S3 Upload using Kernel TLS and sendfile.

Upload a file to AWS S3 using Kernel TLS. 
File can be transferred using sendfile or
using io_uring to send asychronously.
The data is copied directly from
the kernel to AWS S3 and is not copied
into and out of userspace. If the system has
TLS offload in the NIC then it will be used.

For a write up on io_uring:
https://kernel.dk/io_uring.pdf

# Build Environment.
To build use Ubuntu 22.04 (has kernel
support and supported version of OpenSSL).

Install OpenSSL development libraries and io_uring libraries:
```
sudo apt-get install libssl-dev liburing-dev liburing2
```

# To build:
make

# Configure credentials:
```
export AWS_ACCESS_KEY_ID=ASIAXXX5UQEWCXH74WN
export AWS_SECRET_ACCESS_KEY=z1sXXXbEXaAU7jUmn00eL6i66IQeGcHJWGD
export AWS_SESSION_TOKEN=XXXXXXXXXXXXX
```
Note, AWS_SESSION_TOKEN only needed for short lived credentials.

# Load TLS module:
```
$ sudo modprobe tls
$ lsmod | grep tls
tls                   114688  0
```

# To Run:
```
$ ./s3-ktls --splice --file s3-ktls.c  --bucket s3-test --region us-east-2
mmk@bigmemory:~/s3-ktls$ ./s3-ktls --splice --file s3-ktls.c  --bucket s3-test --region us-east-2
Using io_uring splice.
connect failed with 0
TCP connection complete.
SSL handshake complete.
HTTP Request Header>>>>>
PUT /s3-ktls.c HTTP/1.1
Content-Length: 34121
Host: s3-test.s3.us-east-2.amazonaws.com
Date: Wed, 28 Feb 2024 09:36:13 GMT
Connection: closed
Authorization: AWS4-HMAC-SHA256 Credential=ASIA5XXXXXV6ZDF6OA/20240228/us-east-2/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,Signature=11cfea5c308e635ab685c0032a1feaa331be9530bc39d33ed648f1912b3756e5
x-amz-content-sha256: UNSIGNED-PAYLOAD
x-amz-date: 20240228T093613Z
x-amz-security-token: FwoGZXIvYXdXXXXXXXXXXXXXXeSiKGAc7Mp2/AJlIbvfgAXmSjCXLNvdfzsibdpuJRA3pyzpeQ7ZRiLfxTM+A22BfYEkoPMaw9cHVWguQoYsGwH+7WjLDp50lI/PLatyukEi6zamSqFHudXaR9K4/oIxn1N3mQLg0/bz5tAvhih7n9GwD6+vTLTSI7p14bbSepkpiDlSNRrbN+vt3RKMTr+64GMijg4u7PyTVgH1vTeLsmpuDht5w35ELDjgqV4uhHTOycMzx80rAo9quf


<<<<<<Header
HTTP headers sent.
Kernal TLS enabled, using splice.
Spliced 16384 bytes to pipe from file.
Spliced 16384 pipes from pipe to socket
Spliced 16384 bytes to pipe from file.
Spliced 16384 pipes from pipe to socket
Spliced 1353 bytes to pipe from file.
Spliced 1353 pipes from pipe to socket
File contents sent.
Response>>>>
HTTP/1.1 200 OK
x-amz-id-2: DNkQjenroOG8KlWwotdiBCz+SWraKMnIB37Pr7sKFQopl47j5a4loH+QsgDQpl2YpuG4i/sx+nY=
x-amz-request-id: F8AW706ANG83A5GA
Date: Wed, 28 Feb 2024 09:36:15 GMT
x-amz-server-side-encryption: AES256
ETag: "9bb0fc14ffe28f368af7a3c39ab0135a"
Server: AmazonS3
Content-Length: 0
Connection: close


<<<<Response
Server response read, connection closed.

```

# Notes
AWS S3 requires a SHA256 of the request body, this can be disabled
and is done in this case. As the file is sent through sendfile the
application does not see the data to generate the SHA256.

As the kernel is sending the data directly and encrypting and
checksuming the data as part of the TLS protocol it is not clear the value
of adding the SHA256 header. If the user has kept a track of the 
SHA256 of the files outside the filesystem then this SHA256 could be sent,
this would allow detection of corrupt files in the filesystem.

An approach to solving this would be to use eBPF, (https://ebpf.io/). An
eBPF program could be attached to the socket sending the data. It could
generate the SHA256 while sendfile is sending the data - when sendfile is
complete the application could retrieve the SHA256 and send it as a trailer
over the socket. 

