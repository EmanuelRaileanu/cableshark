import socket
import struct


def ethHeader(data):
    """
    ethHeader(data) -> dict

    Unpack and destructure the ETH header data

    :param data: list(list(str))
    :return: dict
    """
    destinationMac, sourceMac, ethProtocol = struct.unpack("!6s6sH", data)
    return {
        "Protocol": ethProtocol,
        "Source mac": macFormatter(sourceMac),
        "Destination mac": macFormatter(destinationMac)
    }


# IP Header Extraction
def ipHeader(data):
    """
    ipHeader(data) -> dict

    Unpack the IP header data
    Destructure the IP header data
    Convert the source address to string
    Attempt to get the hostname using the source address
    Convert the destination address to string
    Attempt to get the hostname using the destination address

    :param data: list(list(str))
    :return: dict
    """
    unpackedData = struct.unpack("!BBHHHBBHBBBBBBBB", data)
    version, tos, totalLength, identification, fragmentOffset, ttl, protocol, headerChecksum, *_ = unpackedData
    sourceAddress = '.'.join(map(str, unpackedData[8:12]))
    sourceHost = getHost(sourceAddress)
    destinationAddress = '.'.join(map(str, unpackedData[12:]))
    destinationHost = getHost(destinationAddress)
    return {
        'Version': version,
        "Tos": tos,
        "Total length": totalLength,
        "Identification": identification,
        "Fragment": fragmentOffset,
        "TTL": ttl,
        "Protocol": protocol,
        "Header checkSum": headerChecksum,
        "Source address": sourceAddress + ' (' + (sourceHost[0] if sourceHost != 'Unknown' else sourceHost) + ')',
        "Destination address": destinationAddress + ' (' + (
            destinationHost[0] if destinationHost != 'Unknown' else destinationHost) + ')'
    }


# Tcp Header Extraction
def tcpHeader(data):
    """
    tcpHeader(data) -> dict

    Unpack and destructure the TCP header data

    :param data: list(list(str))
    :return: dict
    """
    sourcePort, destinationPort, sequenceNumber, acknowledgeNumber, \
    offsetReserved, tcpFlag, window, checksum, urgentPointer = struct.unpack('!HHLLBBHHH', data)
    return {
        "Source port": sourcePort,
        "Destination port": destinationPort,
        "Sequence number": sequenceNumber,
        "Acknowledge number": acknowledgeNumber,
        "Offset and reserved": offsetReserved,
        "Tcp flag": tcpFlag,
        "Window": window,
        "Checksum": checksum,
        "Urgent pointer": urgentPointer
    }


# UDP Header Extraction
def udpHeader(data):
    """
    udpHeader(data) -> dict

    Unpack and destructure the UDP header data

    :param data: list(list(str))
    :return: dict
    """
    sourcePort, destPort, length, checksum = struct.unpack('!HHHH', data)
    return {
        "Source port": sourcePort,
        "Destination port": destPort,
        "Length": length,
        "Checksum": checksum
    }


# ICMP Header Extraction
def icmpHeader(data):
    """
    icmpHeader(data) -> dict

    Unpack and destructure the ICMP header data

    :param data: list(list(str))
    :return: dict
    """
    icmpType, code, checksum = struct.unpack('!BBH', data)
    return {
        'ICMP type': icmpType,
        "Code": code,
        "Checksum": checksum
    }


def macFormatter(macArray):
    """
    macFormatter(macArray) -> string

    Transform the mac address into a more common and readable format

    :param macArray: list(str)
    :return: str
    """
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % tuple(macArray)


def getHost(ipAddress):
    """
    getHost(ipAddress) -> string

    Attempt to get the hostname using the ip address

    :param ipAddress: str
    :return: str
    """
    try:
        k = socket.gethostbyaddr(ipAddress)
    except socket.error:
        k = 'Unknown'
    return k
