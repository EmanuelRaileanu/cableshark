import struct
import pytest
from unittest.mock import patch

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import main


class TestValidateKeywords:
    def test_valid_keywords(self):
        assert main.validateKeywords(['protocol', 'src', 'dest']) is True

    def test_all_keywords(self):
        assert main.validateKeywords(main.KEYWORDS) is True

    def test_empty_list(self):
        assert main.validateKeywords([]) is True

    def test_invalid_keyword(self):
        assert main.validateKeywords(['invalid']) is False

    def test_mixed_valid_invalid(self):
        assert main.validateKeywords(['protocol', 'invalid']) is False

    def test_single_valid_keyword(self):
        assert main.validateKeywords(['srcport']) is True


class TestValidateProtocol:
    def test_tcp(self):
        assert main.validateProtocol('TCP') is True

    def test_udp(self):
        assert main.validateProtocol('UDP') is True

    def test_icmp(self):
        assert main.validateProtocol('ICMP') is True

    def test_invalid_protocol(self):
        assert main.validateProtocol('HTTP') is False

    def test_lowercase_protocol(self):
        assert main.validateProtocol('tcp') is False

    def test_empty_protocol(self):
        assert main.validateProtocol('') is False


class TestValidateIpAddress:
    def test_valid_ip(self):
        assert main.validateIpAddress('192.168.1.1') is True

    def test_valid_loopback(self):
        assert main.validateIpAddress('127.0.0.1') is True

    def test_valid_all_zeros(self):
        assert main.validateIpAddress('0.0.0.0') is True

    def test_valid_broadcast(self):
        assert main.validateIpAddress('255.255.255.255') is True

    def test_invalid_ip(self):
        assert main.validateIpAddress('999.999.999.999') is False

    def test_invalid_format(self):
        assert main.validateIpAddress('not_an_ip') is False

    def test_empty_string(self):
        assert main.validateIpAddress('') is False

    def test_partial_ip_accepted_by_inet_aton(self):
        # socket.inet_aton accepts shortened IPs (C library behavior)
        assert main.validateIpAddress('192.168.1') is True


class TestValidatePort:
    def test_valid_port(self):
        assert main.validatePort('80') is True

    def test_min_port(self):
        assert main.validatePort('1') is True

    def test_max_port(self):
        assert main.validatePort('65535') is True

    def test_port_zero(self):
        assert main.validatePort('0') is False

    def test_port_too_high(self):
        assert main.validatePort('65536') is False

    def test_negative_port(self):
        assert main.validatePort('-1') is False

    def test_non_numeric_port(self):
        assert main.validatePort('abc') is False

    def test_empty_port(self):
        assert main.validatePort('') is False

    def test_float_port(self):
        assert main.validatePort('80.5') is False

    def test_common_ports(self):
        assert main.validatePort('443') is True
        assert main.validatePort('8080') is True
        assert main.validatePort('22') is True


class TestValidateCommandLineArguments:
    def test_valid_args(self):
        # Should not raise
        main.validateCommandLineArguments(['protocol'], ['TCP'])

    def test_mismatched_lengths(self):
        with pytest.raises(SystemExit) as exc:
            main.validateCommandLineArguments(['protocol', 'src'], ['TCP'])
        assert exc.value.code == 1

    def test_invalid_keyword(self):
        with pytest.raises(SystemExit) as exc:
            main.validateCommandLineArguments(['invalid'], ['value'])
        assert exc.value.code == 2

    def test_empty_args(self):
        # Should not raise
        main.validateCommandLineArguments([], [])


class TestValidateArgDict:
    def test_valid_args(self):
        # Should not raise
        main.validateArgDict({'protocol': 'TCP', 'src': '192.168.1.1'})

    def test_invalid_protocol(self):
        with pytest.raises(SystemExit) as exc:
            main.validateArgDict({'protocol': 'HTTP'})
        assert exc.value.code == 3

    def test_invalid_dest_ip(self):
        with pytest.raises(SystemExit) as exc:
            main.validateArgDict({'dest': 'invalid'})
        assert exc.value.code == 4

    def test_invalid_dest_port(self):
        with pytest.raises(SystemExit) as exc:
            main.validateArgDict({'destport': 'abc'})
        assert exc.value.code == 5

    def test_invalid_src_ip(self):
        with pytest.raises(SystemExit) as exc:
            main.validateArgDict({'src': 'invalid'})
        assert exc.value.code == 6

    def test_invalid_src_port(self):
        with pytest.raises(SystemExit) as exc:
            main.validateArgDict({'srcport': '0'})
        assert exc.value.code == 7

    def test_empty_dict(self):
        # Should not raise
        main.validateArgDict({})


class TestCreateArgDict:
    def test_creates_dict(self):
        result = main.createArgDict(['protocol', 'src'], ['TCP', '192.168.1.1'])
        assert result == {'protocol': 'TCP', 'src': '192.168.1.1'}

    def test_empty_args(self):
        result = main.createArgDict([], [])
        assert result == {}

    def test_single_arg(self):
        result = main.createArgDict(['dest'], ['10.0.0.1'])
        assert result == {'dest': '10.0.0.1'}


class TestParseCommandLineArguments:
    @patch('sys.argv', ['main.py', '--help'])
    def test_help_flag(self):
        with pytest.raises(SystemExit) as exc:
            main.parseCommandLineArguments()
        assert exc.value.code == 0

    @patch('sys.argv', ['main.py', '-h'])
    def test_h_flag(self):
        with pytest.raises(SystemExit) as exc:
            main.parseCommandLineArguments()
        assert exc.value.code == 0

    @patch('sys.argv', ['main.py', '-protocol', 'TCP'])
    def test_parses_protocol(self):
        result = main.parseCommandLineArguments()
        assert result == {'protocol': 'TCP'}

    @patch('sys.argv', ['main.py', '-protocol', 'TCP', '-dest', '10.0.0.1'])
    def test_parses_multiple_args(self):
        result = main.parseCommandLineArguments()
        assert result == {'protocol': 'TCP', 'dest': '10.0.0.1'}

    @patch('sys.argv', ['main.py'])
    def test_no_args(self):
        result = main.parseCommandLineArguments()
        assert result == {}


class TestUnpackProtocolHeader:
    def _build_packet(self, protocol_id, ip_payload_size):
        """Build a fake packet with an IP header and protocol payload."""
        # Minimal IP header (20 bytes)
        ip_hdr = struct.pack('!BBHHHBBHBBBBBBBB',
                             0x45, 0, 40, 0, 0, 64, protocol_id, 0,
                             192, 168, 1, 1, 10, 0, 0, 1)
        payload = b'\x00' * ip_payload_size
        return ip_hdr + payload

    def test_tcp_header(self):
        packet = self._build_packet(6, 20)  # TCP needs 20 bytes after IP
        result = main.unpackProtocolHeader(packet, 6)
        assert result is not None
        assert 'Source port' in result

    def test_udp_header(self):
        packet = self._build_packet(17, 8)  # UDP needs 8 bytes after IP
        result = main.unpackProtocolHeader(packet, 17)
        assert result is not None
        assert 'Source port' in result

    def test_icmp_header(self):
        packet = self._build_packet(1, 6)  # ICMP needs 6 bytes after IP
        result = main.unpackProtocolHeader(packet, 1)
        assert result is not None
        assert 'ICMP type' in result

    def test_unknown_protocol(self):
        packet = self._build_packet(99, 20)
        result = main.unpackProtocolHeader(packet, 99)
        assert result is None

    def test_packet_too_short_for_tcp(self):
        packet = self._build_packet(6, 10)  # Too short for TCP header
        result = main.unpackProtocolHeader(packet, 6)
        assert result is None

    def test_packet_too_short_for_udp(self):
        packet = self._build_packet(17, 4)  # Too short for UDP header
        result = main.unpackProtocolHeader(packet, 17)
        assert result is None

    def test_packet_too_short_for_icmp(self):
        packet = self._build_packet(1, 2)  # Too short for ICMP header
        result = main.unpackProtocolHeader(packet, 1)
        assert result is None


class TestFilterInfo:
    def _make_ip_header(self, protocol=6, src='192.168.1.1', dest='10.0.0.1'):
        return {
            'Protocol': protocol,
            'Source address': f'{src} (Unknown)',
            'Destination address': f'{dest} (Unknown)',
        }

    def _make_proto_header(self, src_port=12345, dst_port=80):
        return {
            'Source port': src_port,
            'Destination port': dst_port,
        }

    @patch('main.printInfo')
    def test_no_filters_prints(self, mock_print):
        main.filterInfo(b'\x00' * 60, self._make_ip_header(), self._make_proto_header(), {})
        mock_print.assert_called_once()

    @patch('main.printInfo')
    def test_protocol_filter_match(self, mock_print):
        main.filterInfo(b'\x00' * 60, self._make_ip_header(protocol=6),
                        self._make_proto_header(), {'protocol': 'TCP'})
        mock_print.assert_called_once()

    @patch('main.printInfo')
    def test_protocol_filter_no_match(self, mock_print):
        main.filterInfo(b'\x00' * 60, self._make_ip_header(protocol=6),
                        self._make_proto_header(), {'protocol': 'UDP'})
        mock_print.assert_not_called()

    @patch('main.printInfo')
    def test_src_filter_match(self, mock_print):
        main.filterInfo(b'\x00' * 60, self._make_ip_header(src='10.0.0.1'),
                        self._make_proto_header(), {'src': '10.0.0.1'})
        mock_print.assert_called_once()

    @patch('main.printInfo')
    def test_src_filter_no_match(self, mock_print):
        main.filterInfo(b'\x00' * 60, self._make_ip_header(src='10.0.0.1'),
                        self._make_proto_header(), {'src': '10.0.0.2'})
        mock_print.assert_not_called()

    @patch('main.printInfo')
    def test_dest_filter_match(self, mock_print):
        main.filterInfo(b'\x00' * 60, self._make_ip_header(dest='10.0.0.1'),
                        self._make_proto_header(), {'dest': '10.0.0.1'})
        mock_print.assert_called_once()

    @patch('main.printInfo')
    def test_destport_filter_match(self, mock_print):
        main.filterInfo(b'\x00' * 60, self._make_ip_header(),
                        self._make_proto_header(dst_port=443), {'destport': '443'})
        mock_print.assert_called_once()

    @patch('main.printInfo')
    def test_srcport_filter_match(self, mock_print):
        main.filterInfo(b'\x00' * 60, self._make_ip_header(),
                        self._make_proto_header(src_port=8080), {'srcport': '8080'})
        mock_print.assert_called_once()

    @patch('main.printInfo')
    def test_icmp_with_port_filter_skipped(self, mock_print):
        main.filterInfo(b'\x00' * 60, self._make_ip_header(protocol=1),
                        {'ICMP type': 8, 'Code': 0, 'Checksum': 0},
                        {'protocol': 'ICMP', 'destport': '80'})
        mock_print.assert_not_called()


class TestConstants:
    def test_protocol_mappings(self):
        assert main.PROTOCOL_MAPPINGS['TCP'] == 6
        assert main.PROTOCOL_MAPPINGS['UDP'] == 17
        assert main.PROTOCOL_MAPPINGS['ICMP'] == 1

    def test_payload_offsets(self):
        assert main.PAYLOAD_OFFSETS['TCP'] == 40
        assert main.PAYLOAD_OFFSETS['UDP'] == 28
        assert main.PAYLOAD_OFFSETS['ICMP'] == 24

    def test_keywords(self):
        assert 'protocol' in main.KEYWORDS
        assert 'src' in main.KEYWORDS
        assert 'dest' in main.KEYWORDS
        assert 'srcport' in main.KEYWORDS
        assert 'destport' in main.KEYWORDS
