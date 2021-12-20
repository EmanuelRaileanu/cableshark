import os
import socket

import unpack


def handleTCPPackets(packetSlice):
    for key, value in unpack.tcpHeader(packetSlice).items():
        print(key, ':', value, end=' | ')


def handleUDPPackets(packetSlice):
    for key, value in unpack.udpHeader(packetSlice).items():
        print(key, ':', value, end=' | ')


def handleICMPPackets(packetSlice):
    for key, value in unpack.icmpHeader(packetSlice).items():
        print(key, ':', value, end=' | ')


def handleHTTPPackets(packet, protocol):
    if protocol == 6:
        print('\n===>> [ ------------ TCP Header ----------- ] <<===')
        handleTCPPackets(packet[20:40])
    elif protocol == 17:
        print('\n===>> [ ------------ UDP Header ----------- ] <<===')
        handleUDPPackets(packet[20:28])
    elif protocol == 1:
        print('\n===>> [ ------------ ICMP Header ----------- ] <<===')
        handleICMPPackets(packet[20:26])


def main():
    # The public network interface
    HOST = socket.gethostbyname_ex(socket.gethostname())
    # Create a raw socket and bind it to the public interface
    if os.name == "nt":
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        print(HOST)
        print('Choose network interface:', HOST[-1])
        chosenNetworkInterface = HOST[-1][-1]
        while chosenNetworkInterface is None:
            chosenNetworkInterface = input('Network interface: ')
            if chosenNetworkInterface not in HOST[-1]:
                print('Choose a valid network interface:', HOST[-1])
                chosenNetworkInterface = None
        s.bind((chosenNetworkInterface, 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

    while True:
        data = s.recvfrom(65565)
        packet = data[0]

        print('\n\n===>> [ ------------ Ethernet Header----- ] <<===')
        for key, value in unpack.ethHeader(packet[0:14]).items():
            print(key, ':', value, end=' | ')

        ipHeaderDict = unpack.ipHeader(packet[:20])
        print('\n===>> [ ------------ IP Header ------------ ] <<===')
        for key, value in ipHeaderDict.items():
            print(key, ':', value, end=' | ')

        handleHTTPPackets(data[0], ipHeaderDict['Protocol'])


if __name__ == "__main__":
    main()
