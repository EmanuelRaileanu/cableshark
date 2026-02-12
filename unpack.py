import socket
import struct
from typing import Dict, Tuple, Union

# Header size constants (in bytes)
ETH_HEADER_SIZE = 14
IP_HEADER_SIZE = 20
TCP_HEADER_SIZE = 20
UDP_HEADER_SIZE = 8
ICMP_HEADER_SIZE = 4

# DNS cache to avoid repeated blocking lookups for the same IP
_dns_cache: Dict[str, Union[str, Tuple]] = {}


def ethHeader(data: bytes) -> Dict[str, object]:
    """
    ethHeader(data) -> dict

    Unpack and destructure the ETH header data

    :param data: bytes
    :return: dict
    """
    destinationMac, sourceMac, ethProtocol = struct.unpack('!6s6sH', data)
    return {
        'Protocol': ethProtocol,
        'Source MAC': macFormatter(sourceMac),
        'Destination MAC': macFormatter(destinationMac)
    }


def ipHeader(data: bytes) -> Dict[str, object]:
    """
    ipHeader(data) -> dict

    Unpack the IP header data
    Destructure the IP header data
    Convert the source address to string
    Attempt to get the hostname using the source address
    Convert the destination address to string
    Attempt to get the hostname using the destination address

    :param data: bytes
    :return: dict
    """
    unpackedData = struct.unpack('!BBHHHBBHBBBBBBBB', data)
    version, tos, totalLength, identification, fragmentOffset, ttl, protocol, headerChecksum, *_ = unpackedData
    sourceAddress = '.'.join(map(str, unpackedData[8:12]))
    sourceHost = getHost(sourceAddress)
    destinationAddress = '.'.join(map(str, unpackedData[12:]))
    destinationHost = getHost(destinationAddress)
    return {
        'Version': version,
        'Tos': tos,
        'Total length': totalLength,
        'Identification': identification,
        'Fragment': fragmentOffset,
        'TTL': ttl,
        'Protocol': protocol,
        'Header checkSum': headerChecksum,
        'Source address': sourceAddress + ' (' + (sourceHost[0] if sourceHost != 'Unknown' else sourceHost) + ')',
        'Destination address': destinationAddress + ' (' + (
            destinationHost[0] if destinationHost != 'Unknown' else destinationHost) + ')'
    }


def tcpHeader(data: bytes) -> Dict[str, object]:
    """
    tcpHeader(data) -> dict

    Unpack and destructure the TCP header data

    :param data: bytes
    :return: dict
    """
    sourcePort, destinationPort, sequenceNumber, acknowledgeNumber, \
    offsetReserved, tcpFlag, window, checksum, urgentPointer = struct.unpack('!HHLLBBHHH', data)
    return {
        'Source port': sourcePort,
        'Destination port': destinationPort,
        'Sequence number': sequenceNumber,
        'Acknowledge number': acknowledgeNumber,
        'Offset and reserved': offsetReserved,
        'Tcp flag': tcpFlag,
        'Window': window,
        'Checksum': checksum,
        'Urgent pointer': urgentPointer
    }


def udpHeader(data: bytes) -> Dict[str, object]:
    """
    udpHeader(data) -> dict

    Unpack and destructure the UDP header data

    :param data: bytes
    :return: dict
    """
    sourcePort, destPort, length, checksum = struct.unpack('!HHHH', data)
    return {
        'Source port': sourcePort,
        'Destination port': destPort,
        'Length': length,
        'Checksum': checksum
    }


def icmpHeader(data: bytes) -> Dict[str, object]:
    """
    icmpHeader(data) -> dict

    Unpack and destructure the ICMP header data

    :param data: bytes
    :return: dict
    """
    icmpType, code, checksum = struct.unpack('!BBH', data)
    return {
        'ICMP type': icmpType,
        'Code': code,
        'Checksum': checksum
    }


def macFormatter(macArray: bytes) -> str:
    """
    macFormatter(macArray) -> string

    Transform the mac address into a more common and readable format

    :param macArray: bytes
    :return: str
    """
    return '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % tuple(macArray)


def getHost(ipAddress: str) -> Union[str, Tuple]:
    """
    getHost(ipAddress) -> string or tuple

    Attempt to get the hostname using the ip address.
    Results are cached to avoid repeated blocking DNS lookups.

    :param ipAddress: str
    :return: str or tuple
    """
    if ipAddress in _dns_cache:
        return _dns_cache[ipAddress]

    try:
        result = socket.gethostbyaddr(ipAddress)
    except socket.error:
        result = 'Unknown'

    _dns_cache[ipAddress] = result
    return result
