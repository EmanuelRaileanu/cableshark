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


def unpackHTTPPackets(packet, protocol):
    """
    handleHTTPPackets(packet, protocol) -> None

    Handle packets for each protocol

    :param packet: list(str)
    :param protocol: str
    :return: None
    """
    if protocol == PROTOCOL_MAPPINGS['TCP']:
        return unpack.tcpHeader(packet[20:40])
    elif protocol == PROTOCOL_MAPPINGS['UDP']:
        return unpack.udpHeader(packet[20:28])
    elif protocol == PROTOCOL_MAPPINGS['ICMP']:
        return unpack.icmpHeader(packet[20:26])


def validateKeywords(keywords):
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


def validateCommandLineArguments(keywords, values):
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


def validateProtocol(protocol):
    """
    validateProtocol(protocol) -> boolean

    If the parsed protocol is not in the list of accepted protocols, return False

    :param protocol: str
    :return: boolean
    """
    if protocol not in PROTOCOL_MAPPINGS.keys():
        return False
    return True


def validateIpAddress(ipAddress):
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


def validatePort(port):
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


def validateArgDict(argDict):
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


def createArgDict(keywords, values):
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


def parseCommandLineArguments():
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
    keywords = list(map(lambda arg: arg.replace('-', ''), args[::2]))
    values = args[1::2]
    validateCommandLineArguments(keywords, values)
    return createArgDict(keywords, values)


def printUnpackedData(data):
    """
    printUnpackedData(data) -> None

    Print data from dictionary

    :param data: dict
    :return: None
    """
    for key, value in data.items():
        print(key, ':', value, end=' | ')


def printProtocolSpecificHeadTitle(protocol):
    """
    printProtocolSpecificHeadTitle(protocol) -> None

    Print protocol specific head title (TCP, UDP, ICMP)

    :param protocol: int
    :return: None
    """
    if protocol == PROTOCOL_MAPPINGS['TCP']:
        print('\n===>> [ ------------ TCP Header ----------- ] <<===')
    elif protocol == PROTOCOL_MAPPINGS['UDP']:
        print('\n===>> [ ------------ UDP Header ----------- ] <<===')
    elif protocol == PROTOCOL_MAPPINGS['ICMP']:
        print('\n===>> [ ------------ ICMP Header ----------- ] <<===')


def printInfo(packet, ipHeaderDict, protocolSpecificHeaderDict):
    """
    printInfo(data, packet, ipHeaderDict) -> None

    Print the gathered information

    :param packet: list(str)
    :param ipHeaderDict: dict
    :param protocolSpecificHeaderDict: dict
    :return: None
    """
    print('\n\n===>> [ ------------ Ethernet Header----- ] <<===')
    printUnpackedData(unpack.ethHeader(packet[0:14]))

    print('\n===>> [ ------------ IP Header ------------ ] <<===')
    printUnpackedData(ipHeaderDict)

    printProtocolSpecificHeadTitle(ipHeaderDict['Protocol'])
    printUnpackedData(protocolSpecificHeaderDict)


def filterInfo(packet, ipHeaderDict, protocolSpecificHeaderDict, clArgs):
    """
    filterInfo(data, packet, ipHeaderDict, commandLineArguments, protocolSpecificHeaderDict: ) -> None

    Filter the sniffed data

    :param packet: list(str)
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
        # Receive all data
        data = s.recvfrom(65535)
        # Get the packet
        packet = data[0]
        # Unpack the IP header
        ipHeaderDict = unpack.ipHeader(packet[:20])
        # Unpack packets according to the protocol through which the packet was received
        protocolSpecificHeaderDict = unpackHTTPPackets(data[0], ipHeaderDict['Protocol'])
        # Filter data based on the filters parsed from the command line arguments
        filterInfo(packet, ipHeaderDict, protocolSpecificHeaderDict, commandLineArguments)


if __name__ == "__main__":
    main()
