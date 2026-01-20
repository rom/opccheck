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
__version__ = "2.0.0"
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
OPC_IID_OPCAsyncIO = uuid.UUID("39c13a53-011e-11d0-9675-0020afd8adb3")  # IOPCAsyncIO (DA 1.0)
OPC_IID_OPCAsyncIO2 = uuid.UUID("39c13a71-011e-11d0-9675-0020afd8adb3")  # IOPCAsyncIO2 (DA 2.0+)
OPC_IID_OPCAsyncIO3 = uuid.UUID("0967b97b-36ef-423e-b6f8-6bff1e40d39d")  # IOPCAsyncIO3 (DA 3.0)
OPC_IID_OPCGroupStateMgt = uuid.UUID("39c13a50-011e-11d0-9675-0020afd8adb3")  # IOPCGroupStateMgt
OPC_IID_OPCGroupStateMgt2 = uuid.UUID("8e368666-d72e-4f78-87ed-647611c61c9f")  # IOPCGroupStateMgt2
OPC_IID_OPCDataCallback = uuid.UUID("39c13a70-011e-11d0-9675-0020afd8adb3")  # IOPCDataCallback
OPC_IID_OPCItemProperties = uuid.UUID("39c13a72-011e-11d0-9675-0020afd8adb3")  # IOPCItemProperties
OPC_IID_OPCItemDeadbandMgt = uuid.UUID("5946da93-8b39-4ec8-ab3d-aa73df5bc86f")  # IOPCItemDeadbandMgt
OPC_IID_OPCItemSamplingMgt = uuid.UUID("3e22d313-f08b-41a5-86c8-95e95cb49ffc")  # IOPCItemSamplingMgt
OPC_IID_OPCPublicGroupStateMgt = uuid.UUID("39c13a51-011e-11d0-9675-0020afd8adb3")  # IOPCPublicGroupStateMgt
OPC_IID_OPCSyncIO2 = uuid.UUID("730f5f0f-55b1-4c81-9e18-ff8a0904e1fa")  # IOPCSyncIO2 (DA 3.0)
OPC_IID_OPCBrowse = uuid.UUID("39227004-a18f-4b57-8b0a-5235670f4468")  # IOPCBrowse (DA 3.0)

# OPC Security Interface UUIDs (from OPC Security Specification)
OPC_IID_OPCSecurityNT = uuid.UUID("7aa83a01-6c77-11d3-84f9-00008630a38b")  # IOPCSecurityNT
OPC_IID_OPCSecurityPrivate = uuid.UUID("7aa83a02-6c77-11d3-84f9-00008630a38b")  # IOPCSecurityPrivate

# OPC HDA (Historical Data Access) Interface UUIDs
OPC_IID_OPCHDA_Server = uuid.UUID("1f1217b0-dee0-11d2-a5e5-000086339399")  # IOPCHDA_Server
OPC_IID_OPCHDA_Browser = uuid.UUID("1f1217b1-dee0-11d2-a5e5-000086339399")  # IOPCHDA_Browser
OPC_IID_OPCHDA_SyncRead = uuid.UUID("1f1217b2-dee0-11d2-a5e5-000086339399")  # IOPCHDA_SyncRead
OPC_IID_OPCHDA_SyncUpdate = uuid.UUID("1f1217b3-dee0-11d2-a5e5-000086339399")  # IOPCHDA_SyncUpdate
OPC_IID_OPCHDA_SyncAnnotations = uuid.UUID("1f1217b4-dee0-11d2-a5e5-000086339399")  # IOPCHDA_SyncAnnotations
OPC_IID_OPCHDA_AsyncRead = uuid.UUID("1f1217b5-dee0-11d2-a5e5-000086339399")  # IOPCHDA_AsyncRead
OPC_IID_OPCHDA_AsyncUpdate = uuid.UUID("1f1217b6-dee0-11d2-a5e5-000086339399")  # IOPCHDA_AsyncUpdate
OPC_IID_OPCHDA_Playback = uuid.UUID("1f1217b7-dee0-11d2-a5e5-000086339399")  # IOPCHDA_Playback

# OPC AE (Alarms & Events) Interface UUIDs
OPC_IID_OPCEventServer = uuid.UUID("65168851-5783-11d1-84a0-00608cb8a7e9")  # IOPCEventServer
OPC_IID_OPCEventSubscriptionMgt = uuid.UUID("65168855-5783-11d1-84a0-00608cb8a7e9")  # IOPCEventSubscriptionMgt
OPC_IID_OPCEventAreaBrowser = uuid.UUID("65168857-5783-11d1-84a0-00608cb8a7e9")  # IOPCEventAreaBrowser
OPC_IID_OPCEventSink = uuid.UUID("6516885f-5783-11d1-84a0-00608cb8a7e9")  # IOPCEventSink
OPC_IID_OPCEventServer2 = uuid.UUID("71bbd273-5783-11d1-84a0-00608cb8a7e9")  # IOPCEventServer2

# OPC Batch Interface UUIDs
OPC_IID_OPCBatchServer = uuid.UUID("8bb4ed50-b314-11d3-b3ea-00c04f8eceaa")  # IOPCBatchServer
OPC_IID_OPCBatchServer2 = uuid.UUID("895a78cf-b0c5-11d4-a0b7-000102a980b1")  # IOPCBatchServer2
OPC_IID_OPCEnumerationSets = uuid.UUID("a8080da0-e23e-11d2-afa7-00c04f539421")  # IOPCEnumerationSets

# OPC DX (Data eXchange) Interface UUIDs
OPC_IID_OPCDXConfiguration = uuid.UUID("a0865c20-a31e-11d3-80b0-00902792fcea")  # IOPCDXConfiguration

# OPC Commands Interface UUIDs
OPC_IID_OPCCommandExecution = uuid.UUID("3104b527-2016-101b-b1f0-00608c9e6c33")  # IOPCCommandExecution

# OPC DA CATID (Category IDs)
CATID_OPCDAServer10 = uuid.UUID("63d5f430-cfe4-11d1-b2c8-0060083ba1fb")  # OPC DA 1.0
CATID_OPCDAServer20 = uuid.UUID("63d5f432-cfe4-11d1-b2c8-0060083ba1fb")  # OPC DA 2.0
CATID_OPCDAServer30 = uuid.UUID("cc603642-66d7-48f1-b69a-b625e73652d7")  # OPC DA 3.0

# OPC HDA CATID
CATID_OPCHDAServer10 = uuid.UUID("7de5b060-e089-11d2-a5e6-000086339399")  # OPC HDA 1.0

# OPC AE CATID
CATID_OPCAEServer10 = uuid.UUID("58e13251-ac87-11d1-84d5-00608cb8a7e9")  # OPC AE 1.0

# Windows Management Instrumentation (WMI) DCOM UUIDs
MSRPC_UUID_WMI = uuid.UUID("8bc3f05e-d86b-11d0-a075-00c04fb68820")  # IWbemLevel1Login

# DCOM/RPC Authentication Providers
MSRPC_UUID_NTLMSSP = uuid.UUID("4a8ee840-a7a6-11c9-8c45-00a0c9b8d6c2")  # NTLMSSP
MSRPC_UUID_SPNEGO = uuid.UUID("4dc8c4d0-8c7a-11c9-8c61-00a0c9b3f1c9")  # SPNEGO

# SAM Remote Protocol (for user enumeration)
MSRPC_UUID_SAMR = uuid.UUID("12345778-1234-abcd-ef00-0123456789ac")  # SAMR

# Local Security Authority (LSA)
MSRPC_UUID_LSARPC = uuid.UUID("12345778-1234-abcd-ef00-0123456789ab")  # LSARPC

# Server Service
MSRPC_UUID_SRVSVC = uuid.UUID("4b324fc8-1670-01d3-1278-5a47bf6ee188")  # SRVSVC

# Scheduler Service
MSRPC_UUID_ATSVC = uuid.UUID("1ff70682-0a51-30e8-076d-740be8cee98b")  # ATSVC

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

class RPCAuthType(Enum):
    NONE = 0
    NTLMSSP = 10
    KERBEROS = 16
    SPNEGO = 9
    SCHANNEL = 14

class OPCDAVersion(Enum):
    UNKNOWN = 0
    DA_1_0 = 1
    DA_2_0 = 2
    DA_3_0 = 3

# List of all available security checks with their metadata
AVAILABLE_CHECKS = {
    "dcom_ports": {"name": "DCOM Port Accessibility", "category": "network", "default": True},
    "endpoint_mapper": {"name": "RPC Endpoint Mapper", "category": "network", "default": True},
    "authentication": {"name": "OPC-DA Authentication", "category": "auth", "default": True},
    "browsing": {"name": "OPC Item Browsing", "category": "opcda", "default": True},
    "remote_activation": {"name": "DCOM Remote Activation", "category": "dcom", "default": True},
    "server_enumeration": {"name": "OPC Server Enumeration", "category": "opcda", "default": True},
    "da_version": {"name": "OPC-DA Version Detection", "category": "opcda", "default": True},
    "sync_io": {"name": "Synchronous I/O Access", "category": "opcda", "default": True},
    "async_io": {"name": "Asynchronous I/O Access", "category": "opcda", "default": True},
    "item_management": {"name": "Item Management Access", "category": "opcda", "default": True},
    "group_management": {"name": "Group Management Access", "category": "opcda", "default": True},
    "item_properties": {"name": "Item Properties Access", "category": "opcda", "default": True},
    "item_deadband": {"name": "Item Deadband Management", "category": "opcda", "default": False},
    "public_groups": {"name": "Public Groups Access", "category": "opcda", "default": False},
    "opc_security": {"name": "OPC Security Interface", "category": "security", "default": True},
    "opc_hda": {"name": "OPC-HDA Interface", "category": "opc_other", "default": False},
    "opc_ae": {"name": "OPC-AE Interface", "category": "opc_other", "default": False},
    "opc_batch": {"name": "OPC Batch Interface", "category": "opc_other", "default": False},
    "opc_dx": {"name": "OPC-DX Interface", "category": "opc_other", "default": False},
    "opc_commands": {"name": "OPC Commands Interface", "category": "opc_other", "default": False},
    "wmi_dcom": {"name": "WMI over DCOM", "category": "windows", "default": False},
    "ntlm_auth": {"name": "NTLM Authentication", "category": "auth", "default": True},
    "null_session": {"name": "Null Session Access", "category": "auth", "default": True},
    "smb_signing": {"name": "SMB Signing", "category": "network", "default": False},
    "samr_access": {"name": "SAM-R Protocol Access", "category": "windows", "default": False},
    "lsa_access": {"name": "LSA Protocol Access", "category": "windows", "default": False},
    "srvsvc_access": {"name": "Server Service Access", "category": "windows", "default": False},
    "callback_interface": {"name": "Data Callback Interface", "category": "opcda", "default": True},
    "connection_limits": {"name": "Connection Limits", "category": "network", "default": False},
}

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

@dataclass
class OPCVersionResult:
    """Result of OPC-DA version detection"""
    version: OPCDAVersion
    supported_versions: List[str]
    da_1_0: bool = False
    da_2_0: bool = False
    da_3_0: bool = False
    error: Optional[str] = None

    def __post_init__(self):
        if not self.supported_versions:
            self.supported_versions = []

@dataclass
class InterfaceCheckResult:
    """Result of checking a specific OPC interface"""
    interface_name: str
    interface_uuid: str
    accessible: bool
    response_time_ms: float = 0.0
    error: Optional[str] = None

@dataclass
class NTLMCheckResult:
    """Result of NTLM authentication probe"""
    ntlm_supported: bool
    ntlm_version: Optional[str] = None
    target_name: Optional[str] = None
    domain_name: Optional[str] = None
    dns_name: Optional[str] = None
    timestamp: Optional[str] = None
    error: Optional[str] = None

@dataclass
class NullSessionResult:
    """Result of null session access check"""
    null_session_allowed: bool
    samr_accessible: bool = False
    lsa_accessible: bool = False
    srvsvc_accessible: bool = False
    error: Optional[str] = None

@dataclass
class ConnectionLimitResult:
    """Result of connection limit testing"""
    max_connections_tested: int
    connections_allowed: int
    rate_limited: bool = False
    error: Optional[str] = None

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

    def check_interface(self, interface_uuid: uuid.UUID, interface_name: str,
                        port: int = 135, version: Tuple[int, int] = (1, 0)) -> InterfaceCheckResult:
        """Generic method to check if a specific OPC interface is accessible"""
        start_time = time.time()
        try:
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, port))

                bind_req = self.dcom._build_rpc_bind(interface_uuid, version)
                sock.send(bind_req)
                response = sock.recv(4096)

                success, error = self.dcom._parse_rpc_bind_ack(response)
                response_time = (time.time() - start_time) * 1000

                return InterfaceCheckResult(
                    interface_name=interface_name,
                    interface_uuid=str(interface_uuid),
                    accessible=success,
                    response_time_ms=response_time,
                    error=error if not success else None
                )
            finally:
                sock.close()
        except Exception as e:
            return InterfaceCheckResult(
                interface_name=interface_name,
                interface_uuid=str(interface_uuid),
                accessible=False,
                response_time_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )

    def detect_opc_da_version(self, port: int = 135) -> OPCVersionResult:
        """Detect supported OPC-DA versions by probing version-specific interfaces"""
        result = OPCVersionResult(
            version=OPCDAVersion.UNKNOWN,
            supported_versions=[]
        )

        # Check DA 1.0 specific interfaces
        da10_check = self.check_interface(OPC_IID_OPCAsyncIO, "IOPCAsyncIO", port, (1, 0))
        result.da_1_0 = da10_check.accessible

        # Check DA 2.0 specific interfaces
        da20_check = self.check_interface(OPC_IID_OPCAsyncIO2, "IOPCAsyncIO2", port, (1, 0))
        result.da_2_0 = da20_check.accessible

        # Check DA 3.0 specific interfaces
        da30_check = self.check_interface(OPC_IID_OPCAsyncIO3, "IOPCAsyncIO3", port, (1, 0))
        da30_check2 = self.check_interface(OPC_IID_OPCBrowse, "IOPCBrowse", port, (1, 0))
        result.da_3_0 = da30_check.accessible or da30_check2.accessible

        # Build supported versions list
        if result.da_1_0:
            result.supported_versions.append("1.0")
        if result.da_2_0:
            result.supported_versions.append("2.0")
        if result.da_3_0:
            result.supported_versions.append("3.0")

        # Determine highest version
        if result.da_3_0:
            result.version = OPCDAVersion.DA_3_0
        elif result.da_2_0:
            result.version = OPCDAVersion.DA_2_0
        elif result.da_1_0:
            result.version = OPCDAVersion.DA_1_0

        return result

    def check_sync_io(self, port: int = 135) -> InterfaceCheckResult:
        """Check if synchronous I/O interface is accessible"""
        return self.check_interface(OPC_IID_OPCSyncIO, "IOPCSyncIO", port)

    def check_sync_io2(self, port: int = 135) -> InterfaceCheckResult:
        """Check if synchronous I/O v2 interface (DA 3.0) is accessible"""
        return self.check_interface(OPC_IID_OPCSyncIO2, "IOPCSyncIO2", port)

    def check_async_io(self, port: int = 135) -> InterfaceCheckResult:
        """Check if asynchronous I/O interface is accessible"""
        return self.check_interface(OPC_IID_OPCAsyncIO2, "IOPCAsyncIO2", port)

    def check_item_management(self, port: int = 135) -> InterfaceCheckResult:
        """Check if item management interface is accessible"""
        return self.check_interface(OPC_IID_OPCItemMgt, "IOPCItemMgt", port)

    def check_group_state_management(self, port: int = 135) -> InterfaceCheckResult:
        """Check if group state management interface is accessible"""
        return self.check_interface(OPC_IID_OPCGroupStateMgt, "IOPCGroupStateMgt", port)

    def check_item_properties(self, port: int = 135) -> InterfaceCheckResult:
        """Check if item properties interface is accessible"""
        return self.check_interface(OPC_IID_OPCItemProperties, "IOPCItemProperties", port)

    def check_item_deadband(self, port: int = 135) -> InterfaceCheckResult:
        """Check if item deadband management interface is accessible"""
        return self.check_interface(OPC_IID_OPCItemDeadbandMgt, "IOPCItemDeadbandMgt", port)

    def check_item_sampling(self, port: int = 135) -> InterfaceCheckResult:
        """Check if item sampling management interface is accessible"""
        return self.check_interface(OPC_IID_OPCItemSamplingMgt, "IOPCItemSamplingMgt", port)

    def check_public_groups(self, port: int = 135) -> InterfaceCheckResult:
        """Check if public groups interface is accessible"""
        return self.check_interface(OPC_IID_OPCPublicGroupStateMgt, "IOPCPublicGroupStateMgt", port)

    def check_data_callback(self, port: int = 135) -> InterfaceCheckResult:
        """Check if data callback interface is accessible"""
        return self.check_interface(OPC_IID_OPCDataCallback, "IOPCDataCallback", port)

    def check_opc_security_nt(self, port: int = 135) -> InterfaceCheckResult:
        """Check if OPC Security NT interface is accessible"""
        return self.check_interface(OPC_IID_OPCSecurityNT, "IOPCSecurityNT", port)

    def check_opc_security_private(self, port: int = 135) -> InterfaceCheckResult:
        """Check if OPC Security Private interface is accessible"""
        return self.check_interface(OPC_IID_OPCSecurityPrivate, "IOPCSecurityPrivate", port)


class OPCHDAChecker:
    """Handles OPC-HDA (Historical Data Access) specific checks"""

    def __init__(self, dcom_checker: 'DCOMChecker'):
        self.dcom = dcom_checker

    def check_hda_server(self, port: int = 135) -> InterfaceCheckResult:
        """Check if HDA Server interface is accessible"""
        return self._check_interface(OPC_IID_OPCHDA_Server, "IOPCHDA_Server", port)

    def check_hda_browser(self, port: int = 135) -> InterfaceCheckResult:
        """Check if HDA Browser interface is accessible"""
        return self._check_interface(OPC_IID_OPCHDA_Browser, "IOPCHDA_Browser", port)

    def check_hda_sync_read(self, port: int = 135) -> InterfaceCheckResult:
        """Check if HDA Sync Read interface is accessible"""
        return self._check_interface(OPC_IID_OPCHDA_SyncRead, "IOPCHDA_SyncRead", port)

    def check_hda_sync_update(self, port: int = 135) -> InterfaceCheckResult:
        """Check if HDA Sync Update interface is accessible (write capability)"""
        return self._check_interface(OPC_IID_OPCHDA_SyncUpdate, "IOPCHDA_SyncUpdate", port)

    def _check_interface(self, interface_uuid: uuid.UUID, name: str, port: int) -> InterfaceCheckResult:
        start_time = time.time()
        try:
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, port))
                bind_req = self.dcom._build_rpc_bind(interface_uuid, (1, 0))
                sock.send(bind_req)
                response = sock.recv(4096)
                success, error = self.dcom._parse_rpc_bind_ack(response)
                return InterfaceCheckResult(
                    interface_name=name,
                    interface_uuid=str(interface_uuid),
                    accessible=success,
                    response_time_ms=(time.time() - start_time) * 1000,
                    error=error if not success else None
                )
            finally:
                sock.close()
        except Exception as e:
            return InterfaceCheckResult(
                interface_name=name,
                interface_uuid=str(interface_uuid),
                accessible=False,
                response_time_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )


class OPCAEChecker:
    """Handles OPC-AE (Alarms & Events) specific checks"""

    def __init__(self, dcom_checker: 'DCOMChecker'):
        self.dcom = dcom_checker

    def check_ae_server(self, port: int = 135) -> InterfaceCheckResult:
        """Check if AE Server interface is accessible"""
        return self._check_interface(OPC_IID_OPCEventServer, "IOPCEventServer", port)

    def check_ae_subscription(self, port: int = 135) -> InterfaceCheckResult:
        """Check if AE Subscription interface is accessible"""
        return self._check_interface(OPC_IID_OPCEventSubscriptionMgt, "IOPCEventSubscriptionMgt", port)

    def check_ae_area_browser(self, port: int = 135) -> InterfaceCheckResult:
        """Check if AE Area Browser interface is accessible"""
        return self._check_interface(OPC_IID_OPCEventAreaBrowser, "IOPCEventAreaBrowser", port)

    def _check_interface(self, interface_uuid: uuid.UUID, name: str, port: int) -> InterfaceCheckResult:
        start_time = time.time()
        try:
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, port))
                bind_req = self.dcom._build_rpc_bind(interface_uuid, (1, 0))
                sock.send(bind_req)
                response = sock.recv(4096)
                success, error = self.dcom._parse_rpc_bind_ack(response)
                return InterfaceCheckResult(
                    interface_name=name,
                    interface_uuid=str(interface_uuid),
                    accessible=success,
                    response_time_ms=(time.time() - start_time) * 1000,
                    error=error if not success else None
                )
            finally:
                sock.close()
        except Exception as e:
            return InterfaceCheckResult(
                interface_name=name,
                interface_uuid=str(interface_uuid),
                accessible=False,
                response_time_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )


class OPCBatchChecker:
    """Handles OPC Batch specific checks"""

    def __init__(self, dcom_checker: 'DCOMChecker'):
        self.dcom = dcom_checker

    def check_batch_server(self, port: int = 135) -> InterfaceCheckResult:
        """Check if Batch Server interface is accessible"""
        return self._check_interface(OPC_IID_OPCBatchServer, "IOPCBatchServer", port)

    def check_enumeration_sets(self, port: int = 135) -> InterfaceCheckResult:
        """Check if Enumeration Sets interface is accessible"""
        return self._check_interface(OPC_IID_OPCEnumerationSets, "IOPCEnumerationSets", port)

    def _check_interface(self, interface_uuid: uuid.UUID, name: str, port: int) -> InterfaceCheckResult:
        start_time = time.time()
        try:
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, port))
                bind_req = self.dcom._build_rpc_bind(interface_uuid, (1, 0))
                sock.send(bind_req)
                response = sock.recv(4096)
                success, error = self.dcom._parse_rpc_bind_ack(response)
                return InterfaceCheckResult(
                    interface_name=name,
                    interface_uuid=str(interface_uuid),
                    accessible=success,
                    response_time_ms=(time.time() - start_time) * 1000,
                    error=error if not success else None
                )
            finally:
                sock.close()
        except Exception as e:
            return InterfaceCheckResult(
                interface_name=name,
                interface_uuid=str(interface_uuid),
                accessible=False,
                response_time_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )


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


class WindowsServicesChecker:
    """Check Windows-specific services and protocols"""

    def __init__(self, dcom_checker: DCOMChecker):
        self.dcom = dcom_checker

    def _check_interface(self, interface_uuid: uuid.UUID, port: int = 135) -> Tuple[bool, Optional[str]]:
        """Generic interface check"""
        try:
            sock = self.dcom._create_socket()
            try:
                sock.connect((self.dcom.resolved_ip, port))
                bind_req = self.dcom._build_rpc_bind(interface_uuid, (1, 0))
                sock.send(bind_req)
                response = sock.recv(4096)
                success, error = self.dcom._parse_rpc_bind_ack(response)
                return success, error
            finally:
                sock.close()
        except Exception as e:
            return False, str(e)

    def check_wmi_dcom(self, port: int = 135) -> InterfaceCheckResult:
        """Check if WMI over DCOM is accessible"""
        start_time = time.time()
        success, error = self._check_interface(MSRPC_UUID_WMI, port)
        return InterfaceCheckResult(
            interface_name="IWbemLevel1Login (WMI)",
            interface_uuid=str(MSRPC_UUID_WMI),
            accessible=success,
            response_time_ms=(time.time() - start_time) * 1000,
            error=error if not success else None
        )

    def check_samr_access(self, port: int = 135) -> InterfaceCheckResult:
        """Check if SAM-R protocol is accessible (user enumeration)"""
        start_time = time.time()
        success, error = self._check_interface(MSRPC_UUID_SAMR, port)
        return InterfaceCheckResult(
            interface_name="SAMR (User Enumeration)",
            interface_uuid=str(MSRPC_UUID_SAMR),
            accessible=success,
            response_time_ms=(time.time() - start_time) * 1000,
            error=error if not success else None
        )

    def check_lsa_access(self, port: int = 135) -> InterfaceCheckResult:
        """Check if LSA protocol is accessible"""
        start_time = time.time()
        success, error = self._check_interface(MSRPC_UUID_LSARPC, port)
        return InterfaceCheckResult(
            interface_name="LSARPC (Security Authority)",
            interface_uuid=str(MSRPC_UUID_LSARPC),
            accessible=success,
            response_time_ms=(time.time() - start_time) * 1000,
            error=error if not success else None
        )

    def check_srvsvc_access(self, port: int = 135) -> InterfaceCheckResult:
        """Check if Server Service is accessible (share enumeration)"""
        start_time = time.time()
        success, error = self._check_interface(MSRPC_UUID_SRVSVC, port)
        return InterfaceCheckResult(
            interface_name="SRVSVC (Server Service)",
            interface_uuid=str(MSRPC_UUID_SRVSVC),
            accessible=success,
            response_time_ms=(time.time() - start_time) * 1000,
            error=error if not success else None
        )

    def check_scheduler_access(self, port: int = 135) -> InterfaceCheckResult:
        """Check if Task Scheduler is accessible"""
        start_time = time.time()
        success, error = self._check_interface(MSRPC_UUID_ATSVC, port)
        return InterfaceCheckResult(
            interface_name="ATSVC (Task Scheduler)",
            interface_uuid=str(MSRPC_UUID_ATSVC),
            accessible=success,
            response_time_ms=(time.time() - start_time) * 1000,
            error=error if not success else None
        )

    def check_null_session(self, port: int = 445) -> NullSessionResult:
        """Check if null session (anonymous) access is allowed via SMB"""
        result = NullSessionResult(null_session_allowed=False)

        # Check various interfaces that may be accessible via null session
        samr_result = self.check_samr_access(135)
        lsa_result = self.check_lsa_access(135)
        srvsvc_result = self.check_srvsvc_access(135)

        result.samr_accessible = samr_result.accessible
        result.lsa_accessible = lsa_result.accessible
        result.srvsvc_accessible = srvsvc_result.accessible

        # If any of these are accessible without auth, null session may be allowed
        result.null_session_allowed = any([
            result.samr_accessible,
            result.lsa_accessible,
            result.srvsvc_accessible
        ])

        return result

    def check_connection_limits(self, port: int = 135, max_attempts: int = 10) -> ConnectionLimitResult:
        """Test connection limits by attempting multiple simultaneous connections"""
        connections = []
        successful = 0

        try:
            for i in range(max_attempts):
                try:
                    sock = self.dcom._create_socket()
                    sock.settimeout(2.0)
                    sock.connect((self.dcom.resolved_ip, port))
                    connections.append(sock)
                    successful += 1
                except (socket.timeout, ConnectionRefusedError, OSError):
                    break

            return ConnectionLimitResult(
                max_connections_tested=max_attempts,
                connections_allowed=successful,
                rate_limited=successful < max_attempts
            )
        finally:
            for sock in connections:
                try:
                    sock.close()
                except Exception:
                    pass


# =============================================================================
# Security Assessment
# =============================================================================

class OPCSecurityAssessor:
    """Performs comprehensive security assessment of OPC-DA servers"""

    def __init__(self, target: str, timeout: float = 5.0, verbose: bool = False,
                 enabled_checks: List[str] = None, disabled_checks: List[str] = None,
                 check_all: bool = False):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self.dcom = DCOMChecker(target, timeout, verbose)
        self.opcda = OPCDAChecker(self.dcom)
        self.activation = RemoteActivationChecker(self.dcom)
        self.hda = OPCHDAChecker(self.dcom)
        self.ae = OPCAEChecker(self.dcom)
        self.batch = OPCBatchChecker(self.dcom)
        self.windows = WindowsServicesChecker(self.dcom)
        self.results: List[SecurityCheckResult] = []

        # Determine which checks to run
        self.enabled_checks = self._resolve_checks(enabled_checks, disabled_checks, check_all)

    def _resolve_checks(self, enabled: List[str], disabled: List[str], check_all: bool) -> set:
        """Resolve which checks should be enabled"""
        if check_all:
            checks = set(AVAILABLE_CHECKS.keys())
        elif enabled:
            checks = set(enabled)
        else:
            # Use default checks
            checks = {k for k, v in AVAILABLE_CHECKS.items() if v["default"]}

        if disabled:
            checks -= set(disabled)

        return checks

    def is_check_enabled(self, check_name: str) -> bool:
        """Check if a specific check is enabled"""
        return check_name in self.enabled_checks

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

    def check_opc_da_version(self) -> OPCVersionResult:
        """Check supported OPC-DA versions"""
        self._log("Detecting OPC-DA version support...")

        version_result = self.opcda.detect_opc_da_version()

        if version_result.supported_versions:
            self._add_result(
                "OPC-DA Version Detection",
                True,
                "INFO",
                f"OPC-DA supported versions: {', '.join(version_result.supported_versions)}",
                {
                    "da_1_0": version_result.da_1_0,
                    "da_2_0": version_result.da_2_0,
                    "da_3_0": version_result.da_3_0,
                    "highest_version": version_result.version.name
                }
            )
        else:
            self._add_result(
                "OPC-DA Version Detection",
                True,
                "INFO",
                "Could not detect OPC-DA version support",
                {"error": version_result.error}
            )

        return version_result

    def check_sync_io_access(self) -> InterfaceCheckResult:
        """Check synchronous I/O interface accessibility"""
        self._log("Checking synchronous I/O interface...")

        result = self.opcda.check_sync_io()

        if result.accessible:
            self._add_result(
                "Synchronous I/O Access",
                False,
                "HIGH",
                "IOPCSyncIO interface is accessible (allows direct read/write operations)",
                {"interface": result.interface_name, "uuid": result.interface_uuid}
            )
        else:
            self._add_result(
                "Synchronous I/O Access",
                True,
                "INFO",
                "IOPCSyncIO interface is not accessible",
                {"error": result.error}
            )

        return result

    def check_async_io_access(self) -> InterfaceCheckResult:
        """Check asynchronous I/O interface accessibility"""
        self._log("Checking asynchronous I/O interface...")

        result = self.opcda.check_async_io()

        if result.accessible:
            self._add_result(
                "Asynchronous I/O Access",
                False,
                "HIGH",
                "IOPCAsyncIO2 interface is accessible (allows async read/write operations)",
                {"interface": result.interface_name, "uuid": result.interface_uuid}
            )
        else:
            self._add_result(
                "Asynchronous I/O Access",
                True,
                "INFO",
                "IOPCAsyncIO2 interface is not accessible",
                {"error": result.error}
            )

        return result

    def check_item_management_access(self) -> InterfaceCheckResult:
        """Check item management interface accessibility"""
        self._log("Checking item management interface...")

        result = self.opcda.check_item_management()

        if result.accessible:
            self._add_result(
                "Item Management Access",
                False,
                "MEDIUM",
                "IOPCItemMgt interface is accessible (allows adding/removing OPC items)",
                {"interface": result.interface_name, "uuid": result.interface_uuid}
            )
        else:
            self._add_result(
                "Item Management Access",
                True,
                "INFO",
                "IOPCItemMgt interface is not accessible",
                {"error": result.error}
            )

        return result

    def check_group_management_access(self) -> InterfaceCheckResult:
        """Check group state management interface accessibility"""
        self._log("Checking group management interface...")

        result = self.opcda.check_group_state_management()

        if result.accessible:
            self._add_result(
                "Group Management Access",
                False,
                "MEDIUM",
                "IOPCGroupStateMgt interface is accessible (allows OPC group manipulation)",
                {"interface": result.interface_name, "uuid": result.interface_uuid}
            )
        else:
            self._add_result(
                "Group Management Access",
                True,
                "INFO",
                "IOPCGroupStateMgt interface is not accessible",
                {"error": result.error}
            )

        return result

    def check_item_properties_access(self) -> InterfaceCheckResult:
        """Check item properties interface accessibility"""
        self._log("Checking item properties interface...")

        result = self.opcda.check_item_properties()

        if result.accessible:
            self._add_result(
                "Item Properties Access",
                False,
                "LOW",
                "IOPCItemProperties interface is accessible (allows reading item metadata)",
                {"interface": result.interface_name, "uuid": result.interface_uuid}
            )
        else:
            self._add_result(
                "Item Properties Access",
                True,
                "INFO",
                "IOPCItemProperties interface is not accessible",
                {"error": result.error}
            )

        return result

    def check_data_callback_access(self) -> InterfaceCheckResult:
        """Check data callback interface accessibility"""
        self._log("Checking data callback interface...")

        result = self.opcda.check_data_callback()

        if result.accessible:
            self._add_result(
                "Data Callback Interface",
                False,
                "MEDIUM",
                "IOPCDataCallback interface is accessible (allows data change subscriptions)",
                {"interface": result.interface_name, "uuid": result.interface_uuid}
            )
        else:
            self._add_result(
                "Data Callback Interface",
                True,
                "INFO",
                "IOPCDataCallback interface is not accessible",
                {"error": result.error}
            )

        return result

    def check_opc_security_interface(self) -> Tuple[InterfaceCheckResult, InterfaceCheckResult]:
        """Check OPC Security interfaces"""
        self._log("Checking OPC Security interfaces...")

        nt_result = self.opcda.check_opc_security_nt()
        private_result = self.opcda.check_opc_security_private()

        if nt_result.accessible:
            self._add_result(
                "OPC Security NT Interface",
                True,
                "INFO",
                "IOPCSecurityNT interface is available (Windows authentication integration)",
                {"interface": nt_result.interface_name}
            )
        if private_result.accessible:
            self._add_result(
                "OPC Security Private Interface",
                True,
                "INFO",
                "IOPCSecurityPrivate interface is available (custom authentication)",
                {"interface": private_result.interface_name}
            )

        if not nt_result.accessible and not private_result.accessible:
            self._add_result(
                "OPC Security Interface",
                False,
                "MEDIUM",
                "No OPC Security interfaces detected - server may lack security controls",
                {"nt_error": nt_result.error, "private_error": private_result.error}
            )

        return nt_result, private_result

    def check_opc_hda_interfaces(self) -> List[InterfaceCheckResult]:
        """Check OPC-HDA interfaces"""
        self._log("Checking OPC-HDA interfaces...")

        results = []
        server_result = self.hda.check_hda_server()
        results.append(server_result)

        if server_result.accessible:
            self._add_result(
                "OPC-HDA Server Interface",
                False,
                "MEDIUM",
                "IOPCHDA_Server interface is accessible (historical data access)",
                {"interface": server_result.interface_name}
            )

            # Check additional HDA interfaces if server is accessible
            browser_result = self.hda.check_hda_browser()
            results.append(browser_result)
            if browser_result.accessible:
                self._add_result(
                    "OPC-HDA Browser Interface",
                    False,
                    "MEDIUM",
                    "IOPCHDA_Browser interface is accessible (can browse historical data)",
                    {"interface": browser_result.interface_name}
                )

            sync_read_result = self.hda.check_hda_sync_read()
            results.append(sync_read_result)
            if sync_read_result.accessible:
                self._add_result(
                    "OPC-HDA Read Interface",
                    False,
                    "MEDIUM",
                    "IOPCHDA_SyncRead interface is accessible (can read historical data)",
                    {"interface": sync_read_result.interface_name}
                )

            sync_update_result = self.hda.check_hda_sync_update()
            results.append(sync_update_result)
            if sync_update_result.accessible:
                self._add_result(
                    "OPC-HDA Update Interface",
                    False,
                    "HIGH",
                    "IOPCHDA_SyncUpdate interface is accessible (can MODIFY historical data)",
                    {"interface": sync_update_result.interface_name}
                )
        else:
            self._add_result(
                "OPC-HDA Interface",
                True,
                "INFO",
                "OPC-HDA interfaces are not accessible",
                {"error": server_result.error}
            )

        return results

    def check_opc_ae_interfaces(self) -> List[InterfaceCheckResult]:
        """Check OPC-AE interfaces"""
        self._log("Checking OPC-AE interfaces...")

        results = []
        server_result = self.ae.check_ae_server()
        results.append(server_result)

        if server_result.accessible:
            self._add_result(
                "OPC-AE Server Interface",
                False,
                "MEDIUM",
                "IOPCEventServer interface is accessible (alarms & events access)",
                {"interface": server_result.interface_name}
            )

            subscription_result = self.ae.check_ae_subscription()
            results.append(subscription_result)
            if subscription_result.accessible:
                self._add_result(
                    "OPC-AE Subscription Interface",
                    False,
                    "MEDIUM",
                    "IOPCEventSubscriptionMgt interface is accessible (can subscribe to events)",
                    {"interface": subscription_result.interface_name}
                )

            browser_result = self.ae.check_ae_area_browser()
            results.append(browser_result)
            if browser_result.accessible:
                self._add_result(
                    "OPC-AE Browser Interface",
                    False,
                    "MEDIUM",
                    "IOPCEventAreaBrowser interface is accessible (can browse alarm areas)",
                    {"interface": browser_result.interface_name}
                )
        else:
            self._add_result(
                "OPC-AE Interface",
                True,
                "INFO",
                "OPC-AE interfaces are not accessible",
                {"error": server_result.error}
            )

        return results

    def check_opc_batch_interfaces(self) -> List[InterfaceCheckResult]:
        """Check OPC Batch interfaces"""
        self._log("Checking OPC Batch interfaces...")

        results = []
        server_result = self.batch.check_batch_server()
        results.append(server_result)

        if server_result.accessible:
            self._add_result(
                "OPC Batch Server Interface",
                False,
                "HIGH",
                "IOPCBatchServer interface is accessible (batch process control)",
                {"interface": server_result.interface_name}
            )
        else:
            self._add_result(
                "OPC Batch Interface",
                True,
                "INFO",
                "OPC Batch interfaces are not accessible",
                {"error": server_result.error}
            )

        return results

    def check_wmi_dcom_access(self) -> InterfaceCheckResult:
        """Check WMI over DCOM accessibility"""
        self._log("Checking WMI over DCOM...")

        result = self.windows.check_wmi_dcom()

        if result.accessible:
            self._add_result(
                "WMI over DCOM",
                False,
                "HIGH",
                "WMI DCOM interface is accessible (allows remote system management)",
                {"interface": result.interface_name}
            )
        else:
            self._add_result(
                "WMI over DCOM",
                True,
                "INFO",
                "WMI DCOM interface is not accessible",
                {"error": result.error}
            )

        return result

    def check_null_session_access(self) -> NullSessionResult:
        """Check null session accessibility"""
        self._log("Checking null session access...")

        result = self.windows.check_null_session()

        if result.null_session_allowed:
            accessible_services = []
            if result.samr_accessible:
                accessible_services.append("SAMR (user enumeration)")
            if result.lsa_accessible:
                accessible_services.append("LSA (security policies)")
            if result.srvsvc_accessible:
                accessible_services.append("SRVSVC (share enumeration)")

            self._add_result(
                "Null Session Access",
                False,
                "HIGH",
                f"Null session access is allowed: {', '.join(accessible_services)}",
                {
                    "samr_accessible": result.samr_accessible,
                    "lsa_accessible": result.lsa_accessible,
                    "srvsvc_accessible": result.srvsvc_accessible
                }
            )
        else:
            self._add_result(
                "Null Session Access",
                True,
                "INFO",
                "Null session access appears to be restricted",
                {}
            )

        return result

    def check_connection_limits(self) -> ConnectionLimitResult:
        """Check connection rate limiting"""
        self._log("Checking connection limits...")

        result = self.windows.check_connection_limits()

        if result.rate_limited:
            self._add_result(
                "Connection Limits",
                True,
                "INFO",
                f"Connection limiting detected ({result.connections_allowed}/{result.max_connections_tested} successful)",
                {
                    "connections_allowed": result.connections_allowed,
                    "max_tested": result.max_connections_tested
                }
            )
        else:
            self._add_result(
                "Connection Limits",
                False,
                "LOW",
                f"No connection limiting detected ({result.connections_allowed} connections allowed)",
                {"connections_allowed": result.connections_allowed}
            )

        return result

    def check_item_deadband_access(self) -> InterfaceCheckResult:
        """Check item deadband management interface"""
        self._log("Checking item deadband management interface...")

        result = self.opcda.check_item_deadband()

        if result.accessible:
            self._add_result(
                "Item Deadband Management",
                False,
                "LOW",
                "IOPCItemDeadbandMgt interface is accessible",
                {"interface": result.interface_name}
            )
        else:
            self._add_result(
                "Item Deadband Management",
                True,
                "INFO",
                "IOPCItemDeadbandMgt interface is not accessible",
                {"error": result.error}
            )

        return result

    def check_public_groups_access(self) -> InterfaceCheckResult:
        """Check public groups interface"""
        self._log("Checking public groups interface...")

        result = self.opcda.check_public_groups()

        if result.accessible:
            self._add_result(
                "Public Groups Access",
                False,
                "MEDIUM",
                "IOPCPublicGroupStateMgt interface is accessible (shared OPC groups)",
                {"interface": result.interface_name}
            )
        else:
            self._add_result(
                "Public Groups Access",
                True,
                "INFO",
                "IOPCPublicGroupStateMgt interface is not accessible",
                {"error": result.error}
            )

        return result

    def run_all_checks(self, scan_ports: bool = True,
                       scan_range: bool = False, quiet: bool = False) -> List[SecurityCheckResult]:
        """Run all security checks"""
        if not quiet:
            print(f"\n{'='*60}")
            print(f"OPC-DA Security Assessment for: {self.target}")
            print(f"Resolved IP: {self.dcom.resolved_ip}")
            print(f"Enabled checks: {len(self.enabled_checks)}")
            print(f"{'='*60}\n")

        # Port scanning
        if scan_ports and self.is_check_enabled("dcom_ports"):
            if not quiet:
                print("[+] Checking DCOM port accessibility...")
            self.check_dcom_ports(scan_range)
            if not quiet:
                print()

        # Endpoint mapper
        if self.is_check_enabled("endpoint_mapper"):
            if not quiet:
                print("[+] Checking RPC Endpoint Mapper...")
            self.check_endpoint_mapper()
            if not quiet:
                print()

        # Authentication
        if self.is_check_enabled("authentication"):
            if not quiet:
                print("[+] Checking authentication requirements...")
            self.check_authentication()
            if not quiet:
                print()

        # Browsing
        if self.is_check_enabled("browsing"):
            if not quiet:
                print("[+] Checking OPC item browsing...")
            self.check_browsing()
            if not quiet:
                print()

        # Remote activation
        if self.is_check_enabled("remote_activation"):
            if not quiet:
                print("[+] Checking DCOM remote activation...")
            self.check_remote_activation()
            if not quiet:
                print()

        # Server enumeration
        if self.is_check_enabled("server_enumeration"):
            if not quiet:
                print("[+] Checking OPC server enumeration...")
            self.check_opc_server_list()
            if not quiet:
                print()

        # OPC-DA Version Detection
        if self.is_check_enabled("da_version"):
            if not quiet:
                print("[+] Detecting OPC-DA version support...")
            self.check_opc_da_version()
            if not quiet:
                print()

        # Synchronous I/O
        if self.is_check_enabled("sync_io"):
            if not quiet:
                print("[+] Checking synchronous I/O interface...")
            self.check_sync_io_access()
            if not quiet:
                print()

        # Asynchronous I/O
        if self.is_check_enabled("async_io"):
            if not quiet:
                print("[+] Checking asynchronous I/O interface...")
            self.check_async_io_access()
            if not quiet:
                print()

        # Item Management
        if self.is_check_enabled("item_management"):
            if not quiet:
                print("[+] Checking item management interface...")
            self.check_item_management_access()
            if not quiet:
                print()

        # Group Management
        if self.is_check_enabled("group_management"):
            if not quiet:
                print("[+] Checking group management interface...")
            self.check_group_management_access()
            if not quiet:
                print()

        # Item Properties
        if self.is_check_enabled("item_properties"):
            if not quiet:
                print("[+] Checking item properties interface...")
            self.check_item_properties_access()
            if not quiet:
                print()

        # Data Callback
        if self.is_check_enabled("callback_interface"):
            if not quiet:
                print("[+] Checking data callback interface...")
            self.check_data_callback_access()
            if not quiet:
                print()

        # OPC Security Interface
        if self.is_check_enabled("opc_security"):
            if not quiet:
                print("[+] Checking OPC Security interfaces...")
            self.check_opc_security_interface()
            if not quiet:
                print()

        # Item Deadband (optional)
        if self.is_check_enabled("item_deadband"):
            if not quiet:
                print("[+] Checking item deadband interface...")
            self.check_item_deadband_access()
            if not quiet:
                print()

        # Public Groups (optional)
        if self.is_check_enabled("public_groups"):
            if not quiet:
                print("[+] Checking public groups interface...")
            self.check_public_groups_access()
            if not quiet:
                print()

        # OPC-HDA (optional)
        if self.is_check_enabled("opc_hda"):
            if not quiet:
                print("[+] Checking OPC-HDA interfaces...")
            self.check_opc_hda_interfaces()
            if not quiet:
                print()

        # OPC-AE (optional)
        if self.is_check_enabled("opc_ae"):
            if not quiet:
                print("[+] Checking OPC-AE interfaces...")
            self.check_opc_ae_interfaces()
            if not quiet:
                print()

        # OPC Batch (optional)
        if self.is_check_enabled("opc_batch"):
            if not quiet:
                print("[+] Checking OPC Batch interfaces...")
            self.check_opc_batch_interfaces()
            if not quiet:
                print()

        # Null Session
        if self.is_check_enabled("null_session"):
            if not quiet:
                print("[+] Checking null session access...")
            self.check_null_session_access()
            if not quiet:
                print()

        # WMI over DCOM (optional)
        if self.is_check_enabled("wmi_dcom"):
            if not quiet:
                print("[+] Checking WMI over DCOM...")
            self.check_wmi_dcom_access()
            if not quiet:
                print()

        # Connection Limits (optional)
        if self.is_check_enabled("connection_limits"):
            if not quiet:
                print("[+] Checking connection limits...")
            self.check_connection_limits()
            if not quiet:
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

def list_available_checks():
    """List all available security checks"""
    print("\nAvailable Security Checks:")
    print("=" * 60)

    categories = {}
    for check_id, info in AVAILABLE_CHECKS.items():
        cat = info["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append((check_id, info))

    category_names = {
        "network": "Network & Ports",
        "auth": "Authentication",
        "opcda": "OPC-DA Interfaces",
        "dcom": "DCOM Services",
        "security": "Security Interfaces",
        "opc_other": "Other OPC Specifications",
        "windows": "Windows Services"
    }

    for cat in ["network", "auth", "opcda", "dcom", "security", "opc_other", "windows"]:
        if cat in categories:
            print(f"\n{category_names.get(cat, cat)}:")
            for check_id, info in sorted(categories[cat]):
                default = " (default)" if info["default"] else ""
                print(f"  {check_id:25} - {info['name']}{default}")

    print("\n" + "=" * 60)
    print("Use --enable-check or --disable-check to control which checks run.")
    print("Use --check-all to enable all checks including optional ones.")


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser"""
    parser = argparse.ArgumentParser(
        prog="opccheck",
        description="""
OPC-DA Security Checker - A comprehensive security assessment tool for OPC-DA
(OLE for Process Control - Data Access) servers and related industrial protocols.

This tool performs extensive security checks including:
- DCOM/RPC connectivity and configuration
- OPC-DA interface accessibility (versions 1.0, 2.0, 3.0)
- OPC-HDA (Historical Data Access) interfaces
- OPC-AE (Alarms & Events) interfaces
- Authentication and authorization testing
- Windows service enumeration

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

  %(prog)s 10.0.0.50 --check-all
      Run all available checks including optional ones

  %(prog)s 192.168.1.100 --enable-check opc_hda --enable-check opc_ae
      Enable specific additional checks

  %(prog)s 192.168.1.100 --disable-check null_session
      Disable specific checks

  %(prog)s 192.168.1.100 --port-range 49152-49200
      Check with extended port scanning

  %(prog)s 192.168.1.100 --no-port-scan
      Skip port scanning, only check security settings

  %(prog)s server.local --timeout 10 --retry 3
      Check with extended timeout and retries

  %(prog)s 192.168.1.100 --json -o results.json
      Output results to JSON file

  %(prog)s 192.168.1.100 --min-severity HIGH
      Only show HIGH and CRITICAL findings

  %(prog)s --list-checks
      List all available security checks

Report bugs to: https://github.com/opccheck/opccheck/issues
        """
    )

    # Required arguments (optional with --list-checks)
    parser.add_argument(
        "target",
        metavar="TARGET",
        nargs="?",
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

    # Check selection options
    check_group = parser.add_argument_group("Check Selection Options")
    check_group.add_argument(
        "--list-checks",
        action="store_true",
        help="List all available security checks and exit"
    )
    check_group.add_argument(
        "--check-all",
        action="store_true",
        help="Enable all security checks including optional ones"
    )
    check_group.add_argument(
        "--enable-check",
        action="append",
        metavar="CHECK",
        dest="enabled_checks",
        help="Enable a specific check (can be used multiple times)"
    )
    check_group.add_argument(
        "--disable-check",
        action="append",
        metavar="CHECK",
        dest="disabled_checks",
        help="Disable a specific check (can be used multiple times)"
    )
    check_group.add_argument(
        "--only-checks",
        metavar="CHECKS",
        help="Run only specified checks (comma-separated list)"
    )

    # OPC-specific options
    opc_group = parser.add_argument_group("OPC-Specific Options")
    opc_group.add_argument(
        "--check-hda",
        action="store_true",
        help="Enable OPC-HDA (Historical Data Access) checks"
    )
    opc_group.add_argument(
        "--check-ae",
        action="store_true",
        help="Enable OPC-AE (Alarms & Events) checks"
    )
    opc_group.add_argument(
        "--check-batch",
        action="store_true",
        help="Enable OPC Batch interface checks"
    )
    opc_group.add_argument(
        "--check-windows",
        action="store_true",
        help="Enable Windows service checks (WMI, SAMR, etc.)"
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output with detailed information"
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode - only show security findings"
    )
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format"
    )
    output_group.add_argument(
        "--xml",
        action="store_true",
        help="Output results in XML format"
    )
    output_group.add_argument(
        "--csv",
        action="store_true",
        help="Output results in CSV format"
    )
    output_group.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write results to file"
    )
    output_group.add_argument(
        "--min-severity",
        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="INFO",
        help="Minimum severity level to display (default: INFO)"
    )
    output_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    output_group.add_argument(
        "--show-passed",
        action="store_true",
        default=True,
        help="Show passed checks in output (default: enabled)"
    )
    output_group.add_argument(
        "--hide-passed",
        action="store_false",
        dest="show_passed",
        help="Hide passed checks, only show findings"
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
    conn_group.add_argument(
        "--retry",
        type=int,
        default=1,
        metavar="COUNT",
        help="Number of retries for failed connections (default: 1)"
    )
    conn_group.add_argument(
        "--delay",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="Delay between checks in seconds (default: 0)"
    )
    conn_group.add_argument(
        "--source-ip",
        metavar="IP",
        help="Source IP address to use for connections"
    )

    # General options
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    return parser


def output_xml(results: List[SecurityCheckResult], target: str, resolved_ip: str):
    """Output results in XML format"""
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print('<?xml version="1.0" encoding="UTF-8"?>')
    print(f'<opccheck_report target="{target}" resolved_ip="{resolved_ip}" timestamp="{timestamp}">')
    print('  <results>')
    for result in results:
        status = "pass" if result.passed else "fail"
        print(f'    <check name="{result.check_name}" status="{status}" severity="{result.severity}">')
        print(f'      <message>{result.message}</message>')
        if result.details:
            print('      <details>')
            for key, value in result.details.items():
                print(f'        <{key}>{value}</{key}>')
            print('      </details>')
        print('    </check>')
    print('  </results>')
    print('</opccheck_report>')


def output_csv(results: List[SecurityCheckResult], target: str):
    """Output results in CSV format"""
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['check_name', 'passed', 'severity', 'message', 'details'])
    for result in results:
        import json
        details_str = json.dumps(result.details) if result.details else ''
        writer.writerow([result.check_name, result.passed, result.severity, result.message, details_str])
    print(output.getvalue())


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

    # Handle --list-checks
    if args.list_checks:
        list_available_checks()
        sys.exit(0)

    # Require target if not listing checks
    if not args.target:
        parser.error("the following arguments are required: TARGET")

    # Validate arguments
    if args.port_range:
        port_range = parse_port_range(args.port_range)
        scan_range = True
    else:
        port_range = None
        scan_range = False

    # Build enabled/disabled checks lists
    enabled_checks = args.enabled_checks or []
    disabled_checks = args.disabled_checks or []

    # Handle --only-checks
    if args.only_checks:
        enabled_checks = args.only_checks.split(',')

    # Handle shortcut options
    if args.check_hda:
        enabled_checks.append("opc_hda")
    if args.check_ae:
        enabled_checks.append("opc_ae")
    if args.check_batch:
        enabled_checks.append("opc_batch")
    if args.check_windows:
        enabled_checks.extend(["wmi_dcom", "samr_access", "lsa_access", "srvsvc_access"])

    try:
        # Create assessor
        assessor = OPCSecurityAssessor(
            target=args.target,
            timeout=args.timeout,
            verbose=args.verbose,
            enabled_checks=enabled_checks if enabled_checks else None,
            disabled_checks=disabled_checks if disabled_checks else None,
            check_all=args.check_all
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
                scan_range=scan_range,
                quiet=args.quiet
            )

            # Filter results by severity if needed
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            min_severity_value = severity_order.get(args.min_severity, 4)
            filtered_results = [
                r for r in results
                if severity_order.get(r.severity, 4) <= min_severity_value
            ]

            # Filter out passed checks if requested
            if not args.show_passed:
                filtered_results = [r for r in filtered_results if not r.passed]

            # Output based on format
            if args.json:
                output_json(filtered_results, args.target)
            elif args.xml:
                output_xml(filtered_results, args.target, assessor.dcom.resolved_ip)
            elif args.csv:
                output_csv(filtered_results, args.target)
            else:
                assessor.print_summary()

            # Write to file if requested
            if args.output:
                import json
                with open(args.output, 'w') as f:
                    output = {
                        "target": args.target,
                        "resolved_ip": assessor.dcom.resolved_ip,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "version": __version__,
                        "checks_enabled": len(assessor.enabled_checks),
                        "results": []
                    }
                    for result in filtered_results:
                        output["results"].append({
                            "check_name": result.check_name,
                            "passed": result.passed,
                            "severity": result.severity,
                            "message": result.message,
                            "details": result.details
                        })
                    json.dump(output, f, indent=2)
                if not args.quiet:
                    print(f"Results written to: {args.output}")

            # Calculate counts for exit code
            critical = sum(1 for r in results if r.severity == "CRITICAL" and not r.passed)
            high = sum(1 for r in results if r.severity == "HIGH" and not r.passed)

            # Exit with appropriate code
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
