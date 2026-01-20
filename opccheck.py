#!/usr/bin/env python3
"""
OPC-DA Security Checker

A command-line tool for security assessment of OPC-DA servers.
Performs various security checks including DCOM connectivity,
authentication requirements, and item browsing permissions.

This tool is intended for authorized security testing and research only.
"""

import argparse
import socket
import struct
import sys
import uuid
import ssl
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List, Tuple, Dict, Any

# Version information
__version__ = "1.0.0"
__author__ = "OPCCheck Security Tool"

# =============================================================================
# Constants and Protocol Definitions
# =============================================================================

# DCOM/RPC Constants
MSRPC_UUID_PORTMAP = uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa")  # EPM
MSRPC_UUID_OXID = uuid.UUID("99fcfec4-5260-101b-bbcb-00aa0021347a")  # OXID Resolver
MSRPC_UUID_IRemUnknown = uuid.UUID("00000131-0000-0000-c000-000000000046")
MSRPC_UUID_IRemUnknown2 = uuid.UUID("00000143-0000-0000-c000-000000000046")

# OPC DA Interface UUIDs
OPC_IID_OPCServerList = uuid.UUID("13486d50-4821-11d2-a494-3cb306c10000")  # IOPCServerList
OPC_IID_OPCServerList2 = uuid.UUID("9dd0b56c-ad9e-43ee-8305-487f3188bf7a")  # IOPCServerList2
OPC_IID_OPCServer = uuid.UUID("39c13a4d-011e-11d0-9675-0020afd8adb3")  # IOPCServer
OPC_IID_OPCItemMgt = uuid.UUID("39c13a54-011e-11d0-9675-0020afd8adb3")  # IOPCItemMgt
OPC_IID_OPCBrowseServerAddressSpace = uuid.UUID("39c13a4e-011e-11d0-9675-0020afd8adb3")  # Browse
OPC_IID_OPCSyncIO = uuid.UUID("39c13a52-011e-11d0-9675-0020afd8adb3")  # IOPCSyncIO

# OPC DA CATID (Category IDs)
CATID_OPCDAServer10 = uuid.UUID("63d5f430-cfe4-11d1-b2c8-0060083ba1fb")  # OPC DA 1.0
CATID_OPCDAServer20 = uuid.UUID("63d5f432-cfe4-11d1-b2c8-0060083ba1fb")  # OPC DA 2.0
CATID_OPCDAServer30 = uuid.UUID("cc603642-66d7-48f1-b69a-b625e73652d7")  # OPC DA 3.0

# Standard DCOM Ports
DCOM_PORT_MAPPER = 135
DCOM_DYNAMIC_PORT_START = 49152
DCOM_DYNAMIC_PORT_END = 65535

# Legacy dynamic port range (Windows 2000/XP/2003)
DCOM_LEGACY_PORT_START = 1024
DCOM_LEGACY_PORT_END = 5000

# RPC Protocol Constants
RPC_VERSION_MAJOR = 5
RPC_VERSION_MINOR = 0

class RPCPacketType(Enum):
    REQUEST = 0
    PING = 1
    RESPONSE = 2
    FAULT = 3
    WORKING = 4
    NOCALL = 5
    REJECT = 6
    ACK = 7
    CL_CANCEL = 8
    FACK = 9
    CANCEL_ACK = 10
    BIND = 11
    BIND_ACK = 12
    BIND_NAK = 13
    ALTER_CONTEXT = 14
    ALTER_CONTEXT_RESP = 15
    SHUTDOWN = 17
    CO_CANCEL = 18
    ORPHANED = 19

class RPCAuthLevel(Enum):
    NONE = 1
    CONNECT = 2
    CALL = 3
    PACKET = 4
    PACKET_INTEGRITY = 5
    PACKET_PRIVACY = 6

# =============================================================================
# Data Classes for Results
# =============================================================================

@dataclass
class PortScanResult:
    """Result of a port scan"""
    port: int
    is_open: bool
    is_dcom: bool
    response_time_ms: float
    error: Optional[str] = None

@dataclass
class AuthCheckResult:
    """Result of authentication check"""
    requires_auth: bool
    auth_level: Optional[str] = None
    anonymous_allowed: bool = False
    ntlm_supported: bool = False
    kerberos_supported: bool = False
    error: Optional[str] = None

@dataclass
class BrowseCheckResult:
    """Result of browsing capability check"""
    can_browse: bool
    item_count: int = 0
    restricted: bool = False
    sample_items: List[str] = None
    error: Optional[str] = None

    def __post_init__(self):
        if self.sample_items is None:
            self.sample_items = []

@dataclass
class SecurityCheckResult:
    """Overall security check result"""
    check_name: str
    passed: bool
    severity: str  # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    message: str
    details: Dict[str, Any] = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}

# =============================================================================
# DCOM/RPC Protocol Implementation
# =============================================================================

class DCOMChecker:
    """Handles DCOM/RPC protocol operations"""

    def __init__(self, target: str, timeout: float = 5.0, verbose: bool = False):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self.resolved_ip = None
        self._resolve_target()

    def _resolve_target(self):
        """Resolve hostname/DNS to IP address"""
        try:
            self.resolved_ip = socket.gethostbyname(self.target)
        except socket.gaierror as e:
            raise ValueError(f"Cannot resolve target '{self.target}': {e}")

    def _create_socket(self) -> socket.socket:
        """Create a configured TCP socket"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        return sock

    def _build_rpc_bind(self, interface_uuid: uuid.UUID,
                        interface_version: Tuple[int, int] = (0, 0),
                        auth_level: int = RPCAuthLevel.NONE.value) -> bytes:
        """Build an RPC BIND request packet"""
        # Transfer syntax (NDR)
        ndr_uuid = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")
        ndr_version = (2, 0)

        # Build context item
        context_item = struct.pack("<H", 0)  # Context ID
        context_item += struct.pack("<B", 1)  # Number of transfer syntaxes
        context_item += struct.pack("<B", 0)  # Reserved
        context_item += interface_uuid.bytes_le
        context_item += struct.pack("<HH", interface_version[0], interface_version[1])
        context_item += ndr_uuid.bytes_le
        context_item += struct.pack("<HH", ndr_version[0], ndr_version[1])

        # Build BIND PDU body
        bind_body = struct.pack("<H", 4280)  # Max transmit frag
        bind_body += struct.pack("<H", 4280)  # Max receive frag
        bind_body += struct.pack("<I", 0)  # Assoc group
        bind_body += struct.pack("<B", 1)  # Num context items
        bind_body += struct.pack("<BBB", 0, 0, 0)  # Reserved
        bind_body += context_item

        # Build RPC header
        call_id = 1
        header = struct.pack("<B", RPC_VERSION_MAJOR)
        header += struct.pack("<B", RPC_VERSION_MINOR)
        header += struct.pack("<B", RPCPacketType.BIND.value)
        header += struct.pack("<B", 0x03)  # Flags: first + last frag
        header += struct.pack("<I", 0x10)  # Data representation (little endian)
        header += struct.pack("<H", 16 + len(bind_body))  # Frag length
        header += struct.pack("<H", 0)  # Auth length
        header += struct.pack("<I", call_id)

        return header + bind_body

    def _parse_rpc_bind_ack(self, data: bytes) -> Tuple[bool, Optional[str]]:
        """Parse RPC BIND_ACK response"""
        if len(data) < 16:
            return False, "Response too short"

        version_major = data[0]
        version_minor = data[1]
        packet_type = data[2]

        if packet_type == RPCPacketType.BIND_ACK.value:
            return True, None
        elif packet_type == RPCPacketType.BIND_NAK.value:
            if len(data) >= 18:
                reason = struct.unpack("<H", data[16:18])[0]
                reasons = {
                    0: "Not specified",
                    1: "Temporary congestion",
                    2: "Local limit exceeded",
                    3: "Called paddr unknown",
                    4: "Protocol version not supported",
                    5: "Default context not supported",
                    6: "User data not readable",
                    7: "No psap available",
                    8: "Authentication type not recognized",
                    9: "Invalid checksum"
                }
                return False, f"BIND_NAK: {reasons.get(reason, f'Unknown ({reason})')}"
            return False, "BIND_NAK received"
        else:
            return False, f"Unexpected packet type: {packet_type}"

    def check_port(self, port: int) -> PortScanResult:
        """Check if a specific port is open and responds to DCOM"""
        start_time = time.time()
        try:
            sock = self._create_socket()
            try:
                sock.connect((self.resolved_ip, port))
                response_time = (time.time() - start_time) * 1000

                # Try to send RPC BIND to verify DCOM
                is_dcom = False
                try:
                    bind_req = self._build_rpc_bind(MSRPC_UUID_PORTMAP)
                    sock.send(bind_req)
                    response = sock.recv(4096)
                    is_dcom, _ = self._parse_rpc_bind_ack(response)
                except Exception:
                    pass

                return PortScanResult(
                    port=port,
                    is_open=True,
                    is_dcom=is_dcom,
                    response_time_ms=response_time
                )
            finally:
                sock.close()
        except socket.timeout:
            return PortScanResult(
                port=port,
                is_open=False,
                is_dcom=False,
                response_time_ms=(time.time() - start_time) * 1000,
                error="Connection timeout"
            )
        except ConnectionRefusedError:
            return PortScanResult(
                port=port,
                is_open=False,
                is_dcom=False,
                response_time_ms=(time.time() - start_time) * 1000,
                error="Connection refused"
            )
        except Exception as e:
            return PortScanResult(
                port=port,
                is_open=False,
                is_dcom=False,
                response_time_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )

    def scan_dynamic_ports(self, port_range: Tuple[int, int] = None,
                           common_only: bool = True) -> List[PortScanResult]:
        """Scan for DCOM dynamic ports"""
        results = []

        if common_only:
            # Scan commonly used DCOM ports
            ports_to_scan = [
                135,   # RPC Endpoint Mapper
                139,   # NetBIOS
                445,   # SMB
                593,   # HTTP RPC Endpoint Mapper
                1024, 1025, 1026, 1027, 1028, 1029, 1030,  # Legacy dynamic
                49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160,  # Modern dynamic
            ]
        else:
            if port_range is None:
                port_range = (DCOM_DYNAMIC_PORT_START, min(DCOM_DYNAMIC_PORT_START + 100, DCOM_DYNAMIC_PORT_END))
            ports_to_scan = list(range(port_range[0], port_range[1] + 1))

        for port in ports_to_scan:
            if self.verbose:
                print(f"  Scanning port {port}...", end='\r')
            result = self.check_port(port)
            if result.is_open:
                results.append(result)

        return results

    def check_endpoint_mapper(self) -> Tuple[bool, List[Dict]]:
        """Query the RPC Endpoint Mapper for OPC-related endpoints"""
        endpoints = []
        try:
            sock = self._create_socket()
            try:
                sock.connect((self.resolved_ip, DCOM_PORT_MAPPER))

                # Send BIND request to endpoint mapper
                bind_req = self._build_rpc_bind(MSRPC_UUID_PORTMAP, (3, 0))
                sock.send(bind_req)
                response = sock.recv(4096)

                success, error = self._parse_rpc_bind_ack(response)
                if not success:
                    return False, []

                # Note: Full endpoint enumeration requires ept_lookup calls
                # For this security check, we verify the mapper is accessible
                return True, endpoints
            finally:
                sock.close()
        except Exception as e:
            return False, []


class OPCDAChecker:
    """Handles OPC-DA specific protocol operations"""

    def __init__(self, dcom_checker: DCOMChecker):
        self.dcom = dcom_checker

    def check_opc_server_list(self, port: int = 135) -> Tuple[bool, Optional[str]]:
        """Check if IOPCServerList interface is accessible"""
        try:
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, port))

                # Try to bind to IOPCServerList
                bind_req = self.dcom._build_rpc_bind(OPC_IID_OPCServerList, (1, 0))
                sock.send(bind_req)
                response = sock.recv(4096)

                success, error = self.dcom._parse_rpc_bind_ack(response)
                return success, error
            finally:
                sock.close()
        except Exception as e:
            return False, str(e)

    def check_unauthenticated_access(self, port: int = 135) -> AuthCheckResult:
        """Check if OPC-DA can be accessed without authentication"""
        result = AuthCheckResult(
            requires_auth=True,
            anonymous_allowed=False
        )

        try:
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, port))

                # Try bind without authentication
                bind_req = self.dcom._build_rpc_bind(
                    OPC_IID_OPCServerList,
                    (1, 0),
                    auth_level=RPCAuthLevel.NONE.value
                )
                sock.send(bind_req)
                response = sock.recv(4096)

                success, error = self.dcom._parse_rpc_bind_ack(response)

                if success:
                    result.requires_auth = False
                    result.anonymous_allowed = True
                    result.auth_level = "NONE"
                else:
                    # Check if it's auth-related rejection
                    if error and "Authentication" in error:
                        result.requires_auth = True
                    result.error = error

            finally:
                sock.close()
        except Exception as e:
            result.error = str(e)

        return result

    def check_browsing_capability(self, port: int = 135) -> BrowseCheckResult:
        """Check if OPC item browsing is possible"""
        result = BrowseCheckResult(can_browse=False)

        try:
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, port))

                # Try to bind to browse interface
                bind_req = self.dcom._build_rpc_bind(
                    OPC_IID_OPCBrowseServerAddressSpace,
                    (1, 0)
                )
                sock.send(bind_req)
                response = sock.recv(4096)

                success, error = self.dcom._parse_rpc_bind_ack(response)

                if success:
                    result.can_browse = True
                else:
                    result.error = error

            finally:
                sock.close()
        except Exception as e:
            result.error = str(e)

        return result


class RemoteActivationChecker:
    """Check DCOM remote activation settings"""

    def __init__(self, dcom_checker: DCOMChecker):
        self.dcom = dcom_checker

    def check_remote_activation(self) -> Tuple[bool, Optional[str]]:
        """
        Check if DCOM remote activation is enabled.

        Remote activation allows clients to remotely instantiate
        COM objects on the server.
        """
        try:
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, DCOM_PORT_MAPPER))

                # Try to bind to OXID Resolver (used for remote activation)
                bind_req = self.dcom._build_rpc_bind(MSRPC_UUID_OXID, (0, 0))
                sock.send(bind_req)
                response = sock.recv(4096)

                success, error = self.dcom._parse_rpc_bind_ack(response)
                return success, error
            finally:
                sock.close()
        except Exception as e:
            return False, str(e)

    def check_iremunknown(self) -> Tuple[bool, Optional[str]]:
        """Check if IRemUnknown interface is accessible"""
        try:
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, DCOM_PORT_MAPPER))

                bind_req = self.dcom._build_rpc_bind(MSRPC_UUID_IRemUnknown2, (0, 0))
                sock.send(bind_req)
                response = sock.recv(4096)

                success, error = self.dcom._parse_rpc_bind_ack(response)
                return success, error
            finally:
                sock.close()
        except Exception as e:
            return False, str(e)


# =============================================================================
# Security Assessment
# =============================================================================

class OPCSecurityAssessor:
    """Performs comprehensive security assessment of OPC-DA servers"""

    def __init__(self, target: str, timeout: float = 5.0, verbose: bool = False):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self.dcom = DCOMChecker(target, timeout, verbose)
        self.opcda = OPCDAChecker(self.dcom)
        self.activation = RemoteActivationChecker(self.dcom)
        self.results: List[SecurityCheckResult] = []

    def _log(self, message: str):
        """Log verbose output"""
        if self.verbose:
            print(f"[*] {message}")

    def _add_result(self, check_name: str, passed: bool, severity: str,
                    message: str, details: Dict = None):
        """Add a security check result"""
        self.results.append(SecurityCheckResult(
            check_name=check_name,
            passed=passed,
            severity=severity,
            message=message,
            details=details or {}
        ))

    def check_dcom_ports(self, scan_range: bool = False) -> List[PortScanResult]:
        """Check for accessible DCOM ports"""
        self._log("Scanning for DCOM ports...")

        port_results = self.dcom.scan_dynamic_ports(common_only=not scan_range)

        open_ports = [r for r in port_results if r.is_open]
        dcom_ports = [r for r in port_results if r.is_dcom]

        if dcom_ports:
            self._add_result(
                "DCOM Port Accessibility",
                False,
                "HIGH",
                f"Found {len(dcom_ports)} accessible DCOM port(s)",
                {"ports": [r.port for r in dcom_ports]}
            )
        elif open_ports:
            self._add_result(
                "DCOM Port Accessibility",
                True,
                "INFO",
                f"Found {len(open_ports)} open port(s), but no DCOM services detected",
                {"ports": [r.port for r in open_ports]}
            )
        else:
            self._add_result(
                "DCOM Port Accessibility",
                True,
                "INFO",
                "No accessible DCOM ports found",
                {}
            )

        return port_results

    def check_endpoint_mapper(self) -> bool:
        """Check RPC Endpoint Mapper accessibility"""
        self._log("Checking RPC Endpoint Mapper...")

        accessible, endpoints = self.dcom.check_endpoint_mapper()

        if accessible:
            self._add_result(
                "RPC Endpoint Mapper",
                False,
                "MEDIUM",
                "RPC Endpoint Mapper (port 135) is accessible from remote host",
                {"accessible": True}
            )
        else:
            self._add_result(
                "RPC Endpoint Mapper",
                True,
                "INFO",
                "RPC Endpoint Mapper is not accessible",
                {"accessible": False}
            )

        return accessible

    def check_authentication(self) -> AuthCheckResult:
        """Check authentication requirements"""
        self._log("Checking authentication requirements...")

        auth_result = self.opcda.check_unauthenticated_access()

        if auth_result.anonymous_allowed:
            self._add_result(
                "OPC-DA Authentication",
                False,
                "CRITICAL",
                "OPC-DA server allows unauthenticated/anonymous access",
                {
                    "anonymous_allowed": True,
                    "auth_level": auth_result.auth_level
                }
            )
        elif auth_result.error and "refused" not in auth_result.error.lower():
            self._add_result(
                "OPC-DA Authentication",
                True,
                "INFO",
                "Authentication check inconclusive - connection issues",
                {"error": auth_result.error}
            )
        else:
            self._add_result(
                "OPC-DA Authentication",
                True,
                "INFO",
                "OPC-DA server appears to require authentication",
                {"requires_auth": auth_result.requires_auth}
            )

        return auth_result

    def check_browsing(self) -> BrowseCheckResult:
        """Check OPC item browsing capability"""
        self._log("Checking OPC item browsing capability...")

        browse_result = self.opcda.check_browsing_capability()

        if browse_result.can_browse:
            self._add_result(
                "OPC Item Browsing",
                False,
                "HIGH",
                "OPC item browsing interface is accessible",
                {"can_browse": True}
            )
        else:
            self._add_result(
                "OPC Item Browsing",
                True,
                "INFO",
                "OPC item browsing interface is not accessible",
                {"error": browse_result.error}
            )

        return browse_result

    def check_remote_activation(self) -> Tuple[bool, bool]:
        """Check DCOM remote activation"""
        self._log("Checking DCOM remote activation...")

        oxid_accessible, oxid_error = self.activation.check_remote_activation()
        irem_accessible, irem_error = self.activation.check_iremunknown()

        if oxid_accessible:
            self._add_result(
                "DCOM Remote Activation",
                False,
                "HIGH",
                "DCOM remote activation (OXID Resolver) is enabled and accessible",
                {"oxid_accessible": True}
            )
        else:
            self._add_result(
                "DCOM Remote Activation",
                True,
                "INFO",
                "DCOM remote activation appears to be restricted",
                {"oxid_accessible": False, "error": oxid_error}
            )

        if irem_accessible:
            self._add_result(
                "IRemUnknown Interface",
                False,
                "MEDIUM",
                "IRemUnknown2 interface is accessible (allows remote COM object manipulation)",
                {"accessible": True}
            )

        return oxid_accessible, irem_accessible

    def check_opc_server_list(self) -> bool:
        """Check IOPCServerList accessibility"""
        self._log("Checking OPC Server List interface...")

        accessible, error = self.opcda.check_opc_server_list()

        if accessible:
            self._add_result(
                "OPC Server Enumeration",
                False,
                "MEDIUM",
                "IOPCServerList interface is accessible (allows enumerating OPC servers)",
                {"accessible": True}
            )
        else:
            self._add_result(
                "OPC Server Enumeration",
                True,
                "INFO",
                "IOPCServerList interface is not accessible",
                {"error": error}
            )

        return accessible

    def run_all_checks(self, scan_ports: bool = True,
                       scan_range: bool = False) -> List[SecurityCheckResult]:
        """Run all security checks"""
        print(f"\n{'='*60}")
        print(f"OPC-DA Security Assessment for: {self.target}")
        print(f"Resolved IP: {self.dcom.resolved_ip}")
        print(f"{'='*60}\n")

        # Port scanning
        if scan_ports:
            print("[+] Checking DCOM port accessibility...")
            self.check_dcom_ports(scan_range)
            print()

        # Endpoint mapper
        print("[+] Checking RPC Endpoint Mapper...")
        self.check_endpoint_mapper()
        print()

        # Authentication
        print("[+] Checking authentication requirements...")
        self.check_authentication()
        print()

        # Browsing
        print("[+] Checking OPC item browsing...")
        self.check_browsing()
        print()

        # Remote activation
        print("[+] Checking DCOM remote activation...")
        self.check_remote_activation()
        print()

        # Server enumeration
        print("[+] Checking OPC server enumeration...")
        self.check_opc_server_list()
        print()

        return self.results

    def print_summary(self):
        """Print a summary of all security check results"""
        print(f"\n{'='*60}")
        print("SECURITY ASSESSMENT SUMMARY")
        print(f"{'='*60}\n")

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_results = sorted(self.results, key=lambda r: severity_order.get(r.severity, 5))

        critical_count = sum(1 for r in self.results if r.severity == "CRITICAL" and not r.passed)
        high_count = sum(1 for r in self.results if r.severity == "HIGH" and not r.passed)
        medium_count = sum(1 for r in self.results if r.severity == "MEDIUM" and not r.passed)

        for result in sorted_results:
            status = "PASS" if result.passed else "FAIL"
            status_char = "[+]" if result.passed else "[-]"
            print(f"{status_char} [{result.severity}] {result.check_name}: {status}")
            print(f"    {result.message}")
            if result.details and self.verbose:
                for key, value in result.details.items():
                    print(f"      - {key}: {value}")
            print()

        print(f"{'='*60}")
        print(f"FINDINGS: {critical_count} Critical, {high_count} High, {medium_count} Medium")

        if critical_count > 0:
            print("\n[!] CRITICAL issues found - immediate action recommended!")
        elif high_count > 0:
            print("\n[!] HIGH severity issues found - remediation recommended.")

        print(f"{'='*60}\n")

        return critical_count, high_count, medium_count


# =============================================================================
# CLI Interface
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser"""
    parser = argparse.ArgumentParser(
        prog="opccheck",
        description="""
OPC-DA Security Checker - A tool for security assessment of OPC-DA servers.

This tool performs various security checks on OPC-DA servers including
DCOM connectivity tests, authentication verification, and browsing
capability assessment.

IMPORTANT: This tool is intended for authorized security testing and
research only. Always obtain proper authorization before testing
systems you do not own.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.100
      Basic security check against IP address

  %(prog)s opcserver.example.com -v
      Verbose check against DNS hostname

  %(prog)s 10.0.0.50 --scan-ports --port-range 49152-49200
      Check with extended port scanning

  %(prog)s 192.168.1.100 --no-port-scan
      Skip port scanning, only check security settings

  %(prog)s server.local --timeout 10
      Check with extended timeout for slow networks

Report bugs to: https://github.com/opccheck/opccheck/issues
        """
    )

    # Required arguments
    parser.add_argument(
        "target",
        metavar="TARGET",
        help="Target OPC-DA server (hostname, DNS name, or IP address)"
    )

    # Port scanning options
    port_group = parser.add_argument_group("Port Scanning Options")
    port_group.add_argument(
        "--scan-ports",
        action="store_true",
        default=True,
        dest="scan_ports",
        help="Scan for accessible DCOM ports (default: enabled)"
    )
    port_group.add_argument(
        "--no-port-scan",
        action="store_false",
        dest="scan_ports",
        help="Disable port scanning"
    )
    port_group.add_argument(
        "--port-range",
        metavar="START-END",
        help="Custom port range to scan (e.g., 49152-49200)"
    )
    port_group.add_argument(
        "--common-ports-only",
        action="store_true",
        default=True,
        help="Only scan commonly used DCOM ports (default)"
    )
    port_group.add_argument(
        "-p", "--port",
        type=int,
        metavar="PORT",
        help="Check a specific port only"
    )

    # Security check options
    check_group = parser.add_argument_group("Security Check Options")
    check_group.add_argument(
        "--check-auth",
        action="store_true",
        default=True,
        help="Check authentication requirements (default: enabled)"
    )
    check_group.add_argument(
        "--check-browse",
        action="store_true",
        default=True,
        help="Check OPC item browsing capability (default: enabled)"
    )
    check_group.add_argument(
        "--check-activation",
        action="store_true",
        default=True,
        help="Check DCOM remote activation (default: enabled)"
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode - only show findings"
    )
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format"
    )
    output_group.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write results to file"
    )

    # Connection options
    conn_group = parser.add_argument_group("Connection Options")
    conn_group.add_argument(
        "-t", "--timeout",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="Connection timeout in seconds (default: 5)"
    )

    # General options
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    return parser


def parse_port_range(port_range_str: str) -> Tuple[int, int]:
    """Parse a port range string like '49152-49200'"""
    try:
        parts = port_range_str.split("-")
        if len(parts) != 2:
            raise ValueError("Invalid format")
        start = int(parts[0])
        end = int(parts[1])
        if start < 1 or end > 65535 or start > end:
            raise ValueError("Invalid port numbers")
        return start, end
    except Exception:
        raise argparse.ArgumentTypeError(
            f"Invalid port range: {port_range_str}. Use format: START-END (e.g., 49152-49200)"
        )


def output_json(results: List[SecurityCheckResult], target: str):
    """Output results in JSON format"""
    import json

    output = {
        "target": target,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": []
    }

    for result in results:
        output["results"].append({
            "check_name": result.check_name,
            "passed": result.passed,
            "severity": result.severity,
            "message": result.message,
            "details": result.details
        })

    print(json.dumps(output, indent=2))


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Validate arguments
    if args.port_range:
        port_range = parse_port_range(args.port_range)
        scan_range = True
    else:
        port_range = None
        scan_range = False

    try:
        # Create assessor
        assessor = OPCSecurityAssessor(
            target=args.target,
            timeout=args.timeout,
            verbose=args.verbose
        )

        # Run checks
        if args.port:
            # Single port check
            if not args.quiet:
                print(f"Checking port {args.port} on {args.target}...")
            result = assessor.dcom.check_port(args.port)
            print(f"Port {args.port}: {'OPEN' if result.is_open else 'CLOSED'}")
            if result.is_dcom:
                print(f"  DCOM service detected")
            if result.error:
                print(f"  Error: {result.error}")
        else:
            # Full assessment
            results = assessor.run_all_checks(
                scan_ports=args.scan_ports,
                scan_range=scan_range
            )

            if args.json:
                output_json(results, args.target)
            else:
                assessor.print_summary()

            # Write to file if requested
            if args.output:
                import json
                with open(args.output, 'w') as f:
                    output = {
                        "target": args.target,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "results": []
                    }
                    for result in results:
                        output["results"].append({
                            "check_name": result.check_name,
                            "passed": result.passed,
                            "severity": result.severity,
                            "message": result.message,
                            "details": result.details
                        })
                    json.dump(output, f, indent=2)
                print(f"Results written to: {args.output}")

            # Exit with appropriate code
            critical, high, _ = assessor.print_summary() if not args.json else (0, 0, 0)
            if critical > 0:
                sys.exit(2)
            elif high > 0:
                sys.exit(1)

    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
