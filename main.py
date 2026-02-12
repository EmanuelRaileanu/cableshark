import os
import socket
import struct
import sys
from typing import Dict, List, Optional

import unpack
from unpack import ETH_HEADER_SIZE, IP_HEADER_SIZE, TCP_HEADER_SIZE, UDP_HEADER_SIZE, ICMP_HEADER_SIZE

KEYWORDS = ['protocol', 'dest', 'destport', 'src', 'srcport']
PROTOCOL_MAPPINGS = {
    'TCP': 6,
    'UDP': 17,
    'ICMP': 1
}

# Payload starts after IP header + protocol-specific header
PAYLOAD_OFFSETS = {
    'TCP': IP_HEADER_SIZE + TCP_HEADER_SIZE,   # 40
    'UDP': IP_HEADER_SIZE + UDP_HEADER_SIZE,   # 28
    'ICMP': IP_HEADER_SIZE + ICMP_HEADER_SIZE, # 26
}

USAGE_TEXT = """\
Usage: python main.py [-protocol <TCP|UDP|ICMP>] [-src <IP>] [-dest <IP>]
                      [-srcport <1-65535>] [-destport <1-65535>]

Options:
  -protocol   Filter by protocol (TCP, UDP, or ICMP)
  -src        Filter by source IP address
  -dest       Filter by destination IP address
  -srcport    Filter by source port (not valid for ICMP)
  -destport   Filter by destination port (not valid for ICMP)
  --help      Show this help message

Examples:
  python main.py
  python main.py -protocol TCP
  python main.py -protocol UDP -dest 192.168.1.1
  python main.py -protocol TCP -src 10.0.0.1 -destport 80

Note: Raw socket access requires elevated privileges (sudo/root on Linux,
      Administrator on Windows).
"""


def unpackProtocolHeader(packet: bytes, protocol: int) -> Optional[Dict[str, object]]:
    """
    unpackProtocolHeader(packet, protocol) -> dict or None

    Unpack the protocol-specific header from the packet.
    Returns None if the protocol is not recognized or the packet is too short.

    :param packet: bytes
    :param protocol: int
    :return: dict or None
    """
    if protocol == PROTOCOL_MAPPINGS['TCP']:
        required = IP_HEADER_SIZE + TCP_HEADER_SIZE
        if len(packet) < required:
            return None
        return unpack.tcpHeader(packet[IP_HEADER_SIZE:required])
    elif protocol == PROTOCOL_MAPPINGS['UDP']:
        required = IP_HEADER_SIZE + UDP_HEADER_SIZE
        if len(packet) < required:
            return None
        return unpack.udpHeader(packet[IP_HEADER_SIZE:required])
    elif protocol == PROTOCOL_MAPPINGS['ICMP']:
        required = IP_HEADER_SIZE + ICMP_HEADER_SIZE
        if len(packet) < required:
            return None
        return unpack.icmpHeader(packet[IP_HEADER_SIZE:required])
    return None


def validateKeywords(keywords: List[str]) -> bool:
    """
    validateKeywords(keywords) -> boolean

    If a parsed keyword is not in the list of accepted keywords, return False

    :param keywords: list(str)
    :return: boolean
    """
    for keyword in keywords:
        if keyword not in KEYWORDS:
            return False
    return True


def validateCommandLineArguments(keywords: List[str], values: List[str]) -> None:
    """
    validateCommandLineArguments(keywords, values) -> None

    Validate the length of the keywords against the length of the values
    Check that the parsed keywords are in the list of accepted keywords

    :param keywords: list(str)
    :param values: list(str)
    :return: None
    """
    if len(keywords) != len(values):
        print(
            'Invalid command line arguments: the length of the values does not coincide with the length of the keywords')
        sys.exit(1)

    if not validateKeywords(keywords):
        print('Invalid command line arguments. Accepted keywords:', KEYWORDS)
        sys.exit(2)


def validateProtocol(protocol: str) -> bool:
    """
    validateProtocol(protocol) -> boolean

    If the parsed protocol is not in the list of accepted protocols, return False

    :param protocol: str
    :return: boolean
    """
    if protocol not in PROTOCOL_MAPPINGS.keys():
        return False
    return True


def validateIpAddress(ipAddress: str) -> bool:
    """
    validateIpAddress(ipAddress) -> boolean

    Use the socket library to check if the ip address is valid

    :param ipAddress: str
    :return: boolean
    """
    try:
        socket.inet_aton(ipAddress)
    except socket.error:
        return False
    return True


def validatePort(port: str) -> bool:
    """
    validatePort(port) -> boolean

    Check that the port is numeric
    Convert the port to an integer
    Check that the specified port matches the allowed port range

    :param port: str
    :return: boolean
    """
    if not port.isnumeric():
        return False

    numericPort = int(port)
    if numericPort < 1 or numericPort > 65535:
        return False

    return True


def validateArgDict(argDict: Dict[str, str]) -> None:
    """
    validateArgDict(argDict) -> None

    - Protocol validation
    - Destination ip validation
    - Destination port validation
    - Source ip validation
    - Source port validation

    :param argDict: dict
    :return: None
    """
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


def createArgDict(keywords: List[str], values: List[str]) -> Dict[str, str]:
    """
    createArgDict(keywords, values) -> dict

    Create and validate the command line arguments dictionary
    Return the dictionary

    :param keywords: list(str)
    :param values: list(str)
    :return: dict
    """
    argDict = {}
    for index, keyword in enumerate(keywords):
        argDict[keyword] = values[index]

    validateArgDict(argDict)

    return argDict


def parseCommandLineArguments() -> Dict[str, str]:
    """
    parseCommandLineArguments() -> dict

    Get the command line arguments except the first one (name of the program)
    Extract the keywords from the command line arguments
    Extract the values from the command line arguments
    Validate the command line arguments
    Create the command line arguments dictionary and return it

    :return: dict
    """
    args = sys.argv[1:]

    if '--help' in args or '-h' in args:
        print(USAGE_TEXT)
        sys.exit(0)

    keywords = list(map(lambda arg: arg.replace('-', ''), args[::2]))
    values = args[1::2]
    validateCommandLineArguments(keywords, values)
    return createArgDict(keywords, values)


def printUnpackedData(data: Dict[str, object]) -> None:
    """
    printUnpackedData(data) -> None

    Print data from dictionary

    :param data: dict
    :return: None
    """
    for key, value in data.items():
        print(key, ':', value, end=' | ')


def printProtocolSpecificData(protocol: int, data: Dict[str, object], packet: bytes) -> None:
    """
    printProtocolSpecificData(protocol, data, packet) -> None

    Print data based on the specific protocol (TCP, UDP, ICMP)

    :param protocol: int
    :param data: dict
    :param packet: bytes
    :return: None
    """
    protocol_names = {v: k for k, v in PROTOCOL_MAPPINGS.items()}
    name = protocol_names.get(protocol)
    if name is None:
        return

    print(f'\n===>> [ ------------ {name} Header ----------- ] <<===')
    printUnpackedData(data)
    print('\nPayload:', packet[PAYLOAD_OFFSETS[name]:])


def printInfo(packet: bytes, ipHeaderDict: Dict[str, object],
              protocolSpecificHeaderDict: Dict[str, object]) -> None:
    """
    printInfo(data, packet, ipHeaderDict) -> None

    Print the gathered information

    :param packet: bytes
    :param ipHeaderDict: dict
    :param protocolSpecificHeaderDict: dict
    :return: None
    """
    print('\n\n===>> [ ------------ Ethernet Header----- ] <<===')
    if len(packet) >= ETH_HEADER_SIZE:
        printUnpackedData(unpack.ethHeader(packet[0:ETH_HEADER_SIZE]))

    print('\n===>> [ ------------ IP Header ------------ ] <<===')
    printUnpackedData(ipHeaderDict)

    printProtocolSpecificData(ipHeaderDict['Protocol'], protocolSpecificHeaderDict, packet)


def filterInfo(packet: bytes, ipHeaderDict: Dict[str, object],
               protocolSpecificHeaderDict: Dict[str, object],
               clArgs: Dict[str, str]) -> None:
    """
    filterInfo(data, packet, ipHeaderDict, commandLineArguments, protocolSpecificHeaderDict) -> None

    Filter the sniffed data

    :param packet: bytes
    :param ipHeaderDict: dict
    :param clArgs: dict
    :param protocolSpecificHeaderDict: dict
    :return: None
    """
    if 'protocol' in clArgs and clArgs['protocol'].upper() == 'ICMP' and ('destport' in clArgs or 'srcport' in clArgs):
        return

    if 'protocol' in clArgs and ipHeaderDict['Protocol'] != PROTOCOL_MAPPINGS[clArgs['protocol'].upper()]:
        return

    if 'dest' in clArgs and ipHeaderDict['Destination address'].split(' ')[0] != clArgs['dest']:
        return

    if 'src' in clArgs and ipHeaderDict['Source address'].split(' ')[0] != clArgs['src']:
        return

    if 'destport' in clArgs and protocolSpecificHeaderDict['Destination port'] != int(clArgs['destport']):
        return

    if 'srcport' in clArgs and protocolSpecificHeaderDict['Source port'] != int(clArgs['srcport']):
        return

    printInfo(packet, ipHeaderDict, protocolSpecificHeaderDict)


def main() -> None:
    commandLineArguments = parseCommandLineArguments()
    # The public network interface
    HOST = socket.gethostbyname_ex(socket.gethostname())
    # Create a raw socket and bind it to the public interface
    if os.name == "nt":
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        print('Choose network interface:', HOST[-1])
        chosenNetworkInterface = None
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
        # Receive all data
        data = s.recvfrom(65535)
        # Get the packet
        packet = data[0]

        # Validate packet length before unpacking
        if len(packet) < IP_HEADER_SIZE:
            continue

        # Unpack the IP header
        ipHeaderDict = unpack.ipHeader(packet[:IP_HEADER_SIZE])

        # Unpack packets according to the protocol
        protocolSpecificHeaderDict = unpackProtocolHeader(packet, ipHeaderDict['Protocol'])

        # Skip packets with unrecognized protocols or malformed headers
        if protocolSpecificHeaderDict is None:
            continue

        # Filter data based on the filters parsed from the command line arguments
        filterInfo(packet, ipHeaderDict, protocolSpecificHeaderDict, commandLineArguments)


if __name__ == "__main__":
    main()
