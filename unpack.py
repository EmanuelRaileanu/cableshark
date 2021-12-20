import socket
import struct


def ethHeader(data):
    destinationMac, sourceMac, ethProtocol = struct.unpack("!6s6sH", data)
    return {
        "Protocol": ethProtocol,
        "Source mac": macFormatter(sourceMac),
        "Destination mac": macFormatter(destinationMac)
    }



# ICMP HEADER Extraction
def icmpHeader(data):
    icmph = struct.unpack('!BBH', data)
    icmp_type = icmph[0]
    code = icmph[1]
    checksum = icmph[2]
    return {
        'ICMP type': icmp_type,
        "Code": code,
        "Checksum": checksum
    }


# UDP Header Extraction
def udpHeader(data):
    sourcePort, destPort, length, checksum = struct.unpack('!HHHH', data)
    return {
        "Source port": sourcePort,
        "Destination port": destPort,
        "Length": length,
        "Checksum": checksum
    }


# IP Header Extraction
def ipHeader(data):
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


def macFormatter(a):
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])


def getHost(q):
    try:
        k = socket.gethostbyaddr(q)
    except:
        k = 'Unknown'
    return k
