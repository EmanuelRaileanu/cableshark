import socket
import struct

# The public network interface
HOST = socket.gethostbyname_ex(socket.gethostname())
# Create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

print(HOST)
print('Choose network interface:', HOST[-1])
chosenHost = None
while chosenHost is None:
    chosenHost = input('Network interface: ')
    if chosenHost not in HOST[-1]:
        print('Choose a valid network interface:', HOST[-1])
        chosenHost = None

s.bind((chosenHost, 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Receive all packages
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# Receive a package
while True:
    data = s.recvfrom(65565)
    packet = data[0]
    header = struct.unpack('!BBHHHBBHBBBBBBBB', packet[:20])
    if header[6] == 6:  # header[6] is the field of the Protocol
        print("TCP", '.'.join(map(str, header[8:12])), '->', '.'.join(map(str, header[12:])))
    elif header[6] == 17:
        print("UDP", '.'.join(map(str, header[8:12])), '->', '.'.join(map(str, header[12:])))
    elif header[5] == 1:
        print("ICMP", '.'.join(map(str, header[8:12])), '->', '.'.join(map(str, header[12:])))
