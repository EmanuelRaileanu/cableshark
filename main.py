import os
import socket
import sys

import unpack

KEYWORDS = ['protocol', 'dest', 'destport', 'src', 'srcport']
PROTOCOL_MAPPINGS = {
    'TCP': 6,
    'UDP': 17,
    'ICMP': 1
}


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
    if protocol == PROTOCOL_MAPPINGS['TCP']:
        print('\n===>> [ ------------ TCP Header ----------- ] <<===')
        handleTCPPackets(packet[20:40])
    elif protocol == PROTOCOL_MAPPINGS['UDP']:
        print('\n===>> [ ------------ UDP Header ----------- ] <<===')
        handleUDPPackets(packet[20:28])
    elif protocol == PROTOCOL_MAPPINGS['ICMP']:
        print('\n===>> [ ------------ ICMP Header ----------- ] <<===')
        handleICMPPackets(packet[20:26])


def validateKeywords(keywords):
    for keyword in keywords:
        if keyword not in KEYWORDS:
            return False
    return True


def validateCommandLineArguments(keywords, values):
    if len(keywords) != len(values):
        print(
            'Invalid command line arguments: the length of the values does not coincide with the length of the keywords')
        sys.exit(1)

    if not validateKeywords(keywords):
        print('Invalid command line arguments. Accepted keywords:', KEYWORDS)
        sys.exit(2)


def validateProtocol(protocol):
    if protocol not in PROTOCOL_MAPPINGS.keys():
        return False
    return True


def validateIpAddress(ipAddress):
    try:
        socket.inet_aton(ipAddress)
    except socket.error:
        return False
    return True


def validatePort(port):
    if not port.isnumeric():
        return False
    numericPort = int(port)
    if numericPort < 1 or numericPort > 65535:
        return False
    return True


def validateArgDict(argDict):
    if 'protocol' in argDict and not validateProtocol(argDict['protocol'].upper()):
        print('Protocol not supported. Accepted values:', list(PROTOCOL_MAPPINGS.keys()))
        sys.exit(3)

    if 'dest' in argDict and not validateIpAddress(argDict['dest']):
        print('The destination ip is invalid.')
        sys.exit(4)

    if 'destport' in argDict and not validatePort(argDict['destport']):
        print('The destination port is invalid.')
        sys.exit(5)

    if 'src' in argDict and not validateIpAddress(argDict['src']):
        print('The source ip is invalid.')
        sys.exit(6)

    if 'srcport' in argDict and not validatePort(argDict['srcport']):
        print('The source port is invalid.')
        sys.exit(7)


def createArgDictionary(keywords, values):
    argDict = {}
    for index, keyword in enumerate(keywords):
        argDict[keyword] = values[index]
    validateArgDict(argDict)
    return argDict


def parseCommandLineArguments():
    """Get the command line arguments except the first one (name of the program)"""
    args = sys.argv[1:]
    """Extract the keywords from the command line arguments"""
    keywords = list(map(lambda arg: arg.replace('-', ''), args[::2]))
    """Extract the values from the command line arguments"""
    values = args[1::2]
    """Validate the command line arguments"""
    validateCommandLineArguments(keywords, values)
    """Create the command line arguments dictionary and return it"""
    return createArgDictionary(keywords, values)


def main():
    commandLineArguments = parseCommandLineArguments()
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
        ipHeaderDict = unpack.ipHeader(packet[:20])

        if ipHeaderDict['Protocol'] == PROTOCOL_MAPPINGS[commandLineArguments['protocol'].upper()]:
            print('\n\n===>> [ ------------ Ethernet Header----- ] <<===')
            for key, value in unpack.ethHeader(packet[0:14]).items():
                print(key, ':', value, end=' | ')

            print('\n===>> [ ------------ IP Header ------------ ] <<===')
            for key, value in ipHeaderDict.items():
                print(key, ':', value, end=' | ')

            handleHTTPPackets(data[0], ipHeaderDict['Protocol'])


if __name__ == "__main__":
    main()
