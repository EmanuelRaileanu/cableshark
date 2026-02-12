import struct
from unittest.mock import patch

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import unpack


class TestMacFormatter:
    def test_formats_standard_mac(self):
        mac_bytes = b'\xaa\xbb\xcc\xdd\xee\xff'
        assert unpack.macFormatter(mac_bytes) == 'aa:bb:cc:dd:ee:ff'

    def test_formats_zero_mac(self):
        mac_bytes = b'\x00\x00\x00\x00\x00\x00'
        assert unpack.macFormatter(mac_bytes) == '00:00:00:00:00:00'

    def test_formats_broadcast_mac(self):
        mac_bytes = b'\xff\xff\xff\xff\xff\xff'
        assert unpack.macFormatter(mac_bytes) == 'ff:ff:ff:ff:ff:ff'


class TestEthHeader:
    def test_unpacks_ethernet_frame(self):
        # Destination MAC: aa:bb:cc:dd:ee:ff, Source MAC: 11:22:33:44:55:66, Protocol: 0x0800 (IPv4)
        data = b'\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00'
        result = unpack.ethHeader(data)
        assert result['Destination MAC'] == 'aa:bb:cc:dd:ee:ff'
        assert result['Source MAC'] == '11:22:33:44:55:66'
        assert result['Protocol'] == 0x0800

    def test_unpacks_arp_protocol(self):
        data = b'\xff\xff\xff\xff\xff\xff\x11\x22\x33\x44\x55\x66\x08\x06'
        result = unpack.ethHeader(data)
        assert result['Protocol'] == 0x0806


class TestIpHeader:
    def _build_ip_header(self, protocol=6, src=(192, 168, 1, 1), dst=(10, 0, 0, 1)):
        """Build a minimal 20-byte IP header."""
        version_ihl = 0x45
        tos = 0
        total_length = 40
        identification = 1234
        fragment = 0
        ttl = 64
        checksum = 0
        return struct.pack('!BBHHHBBHBBBBBBBB',
                           version_ihl, tos, total_length, identification,
                           fragment, ttl, protocol, checksum,
                           src[0], src[1], src[2], src[3],
                           dst[0], dst[1], dst[2], dst[3])

    @patch('unpack.getHost', return_value='Unknown')
    def test_unpacks_tcp_protocol(self, mock_host):
        data = self._build_ip_header(protocol=6)
        result = unpack.ipHeader(data)
        assert result['Protocol'] == 6
        assert result['TTL'] == 64
        assert result['Version'] == 0x45

    @patch('unpack.getHost', return_value='Unknown')
    def test_unpacks_source_address(self, mock_host):
        data = self._build_ip_header(src=(10, 20, 30, 40))
        result = unpack.ipHeader(data)
        assert '10.20.30.40' in result['Source address']

    @patch('unpack.getHost', return_value='Unknown')
    def test_unpacks_destination_address(self, mock_host):
        data = self._build_ip_header(dst=(172, 16, 0, 1))
        result = unpack.ipHeader(data)
        assert '172.16.0.1' in result['Destination address']

    @patch('unpack.getHost', return_value=('example.com', [], ['1.2.3.4']))
    def test_includes_hostname_when_resolved(self, mock_host):
        data = self._build_ip_header()
        result = unpack.ipHeader(data)
        assert 'example.com' in result['Source address']


class TestTcpHeader:
    def test_unpacks_tcp_header(self):
        # Source port: 12345, Dest port: 80, Seq: 100, Ack: 200
        data = struct.pack('!HHLLBBHHH', 12345, 80, 100, 200, 0x50, 0x02, 65535, 0, 0)
        result = unpack.tcpHeader(data)
        assert result['Source port'] == 12345
        assert result['Destination port'] == 80
        assert result['Sequence number'] == 100
        assert result['Acknowledge number'] == 200
        assert result['Window'] == 65535

    def test_unpacks_high_ports(self):
        data = struct.pack('!HHLLBBHHH', 65535, 65534, 0, 0, 0, 0, 0, 0, 0)
        result = unpack.tcpHeader(data)
        assert result['Source port'] == 65535
        assert result['Destination port'] == 65534


class TestUdpHeader:
    def test_unpacks_udp_header(self):
        data = struct.pack('!HHHH', 5353, 53, 100, 0xabcd)
        result = unpack.udpHeader(data)
        assert result['Source port'] == 5353
        assert result['Destination port'] == 53
        assert result['Length'] == 100
        assert result['Checksum'] == 0xabcd

    def test_unpacks_zero_length(self):
        data = struct.pack('!HHHH', 1024, 1025, 0, 0)
        result = unpack.udpHeader(data)
        assert result['Length'] == 0


class TestIcmpHeader:
    def test_unpacks_echo_request(self):
        # Type 8 = echo request, code 0
        data = struct.pack('!BBH', 8, 0, 0x1234)
        result = unpack.icmpHeader(data)
        assert result['ICMP type'] == 8
        assert result['Code'] == 0
        assert result['Checksum'] == 0x1234

    def test_unpacks_echo_reply(self):
        data = struct.pack('!BBH', 0, 0, 0)
        result = unpack.icmpHeader(data)
        assert result['ICMP type'] == 0

    def test_unpacks_destination_unreachable(self):
        data = struct.pack('!BBH', 3, 1, 0)
        result = unpack.icmpHeader(data)
        assert result['ICMP type'] == 3
        assert result['Code'] == 1


class TestGetHost:
    def setup_method(self):
        unpack._dns_cache.clear()

    @patch('socket.gethostbyaddr', return_value=('example.com', [], ['1.2.3.4']))
    def test_returns_hostname(self, mock_dns):
        result = unpack.getHost('1.2.3.4')
        assert result[0] == 'example.com'

    @patch('socket.gethostbyaddr', side_effect=OSError('DNS failed'))
    def test_returns_unknown_on_failure(self, mock_dns):
        result = unpack.getHost('1.2.3.4')
        assert result == 'Unknown'

    @patch('socket.gethostbyaddr', return_value=('example.com', [], ['1.2.3.4']))
    def test_caches_results(self, mock_dns):
        unpack.getHost('1.2.3.4')
        unpack.getHost('1.2.3.4')
        # Should only call DNS once due to caching
        mock_dns.assert_called_once()

    @patch('socket.gethostbyaddr', side_effect=OSError('DNS failed'))
    def test_caches_unknown_results(self, mock_dns):
        unpack.getHost('10.0.0.1')
        unpack.getHost('10.0.0.1')
        mock_dns.assert_called_once()


class TestConstants:
    def test_header_sizes(self):
        assert unpack.ETH_HEADER_SIZE == 14
        assert unpack.IP_HEADER_SIZE == 20
        assert unpack.TCP_HEADER_SIZE == 20
        assert unpack.UDP_HEADER_SIZE == 8
        assert unpack.ICMP_HEADER_SIZE == 4
