# OPCCheck - OPC-DA Security Checker

A comprehensive command-line tool for security assessment of OPC-DA (OLE for Process Control - Data Access) servers and related industrial protocols. This tool performs extensive security checks including DCOM connectivity tests, OPC interface accessibility verification, authentication testing, and more.

## Features

### Core OPC-DA Security Checks
- **DCOM Port Scanning**: Test dynamic ports to identify accessible DCOM endpoints
- **Authentication Checks**: Verify if OPC-DA connections can be performed without authentication
- **OPC Item Browsing**: Check if clients can browse OPC items and whether restrictions are in place
- **Remote Activation Detection**: Determine if DCOM remote activation is enabled
- **OPC Server Enumeration**: Check if the IOPCServerList interface is accessible
- **OPC-DA Version Detection**: Detect supported OPC-DA versions (1.0, 2.0, 3.0)

### Extended OPC-DA Interface Checks
- **Synchronous I/O (IOPCSyncIO)**: Check direct read/write operation access
- **Asynchronous I/O (IOPCAsyncIO2/3)**: Check async read/write operation access
- **Item Management (IOPCItemMgt)**: Check ability to add/remove OPC items
- **Group Management (IOPCGroupStateMgt)**: Check OPC group manipulation access
- **Item Properties (IOPCItemProperties)**: Check item metadata access
- **Data Callback (IOPCDataCallback)**: Check data subscription capabilities
- **Item Deadband Management**: Check deadband configuration access
- **Public Groups**: Check shared OPC group access

### OPC Security Specification Checks
- **IOPCSecurityNT**: Windows authentication integration
- **IOPCSecurityPrivate**: Custom authentication mechanisms

### Additional OPC Specifications (Optional)
- **OPC-HDA (Historical Data Access)**: Historical data read/write capabilities
- **OPC-AE (Alarms & Events)**: Event subscription and browsing
- **OPC Batch**: Batch process control interfaces
- **OPC-DX**: Data exchange interfaces
- **OPC Commands**: Command execution interfaces

### Windows/DCOM Security Checks
- **Null Session Access**: Check anonymous access to Windows services
- **WMI over DCOM**: Remote Windows management access
- **SAM-R Protocol**: User enumeration capabilities
- **LSA Protocol**: Security policy access
- **Server Service (SRVSVC)**: Share enumeration
- **Connection Limits**: Rate limiting detection

### Output Formats
- **Console Output**: Human-readable with severity levels
- **JSON**: Structured output for automation
- **XML**: Integration with security tools
- **CSV**: Spreadsheet-compatible format

## Requirements

- Python 3.8 or higher
- No external dependencies (uses only Python standard library)

## Installation

### From Source

```bash
git clone https://github.com/opccheck/opccheck.git
cd opccheck
pip install .
```

### Manual Installation

```bash
# Make the script executable
chmod +x opccheck.py

# Optionally, copy to a directory in your PATH
sudo cp opccheck.py /usr/local/bin/opccheck

# Install man page (optional)
sudo cp opccheck.1 /usr/local/share/man/man1/
sudo mandb
```

### Development Installation

```bash
pip install -e .
```

## Usage

### Basic Usage

```bash
# Check an OPC-DA server by IP address
opccheck 192.168.1.100

# Check an OPC-DA server by hostname
opccheck opcserver.example.com

# List all available security checks
opccheck --list-checks
```

### Command Line Options

```
usage: opccheck [-h] [--scan-ports] [--no-port-scan] [--port-range START-END]
                [--common-ports-only] [-p PORT] [--list-checks] [--check-all]
                [--enable-check CHECK] [--disable-check CHECK] [--only-checks CHECKS]
                [--check-hda] [--check-ae] [--check-batch] [--check-windows]
                [-v] [-q] [--json] [--xml] [--csv] [-o FILE]
                [--min-severity {INFO,LOW,MEDIUM,HIGH,CRITICAL}] [--no-color]
                [--show-passed] [--hide-passed] [-t SECONDS] [--retry COUNT]
                [--delay SECONDS] [--source-ip IP] [-V]
                [TARGET]

positional arguments:
  TARGET                Target OPC-DA server (hostname, DNS name, or IP address)

Port Scanning Options:
  --scan-ports          Scan for accessible DCOM ports (default: enabled)
  --no-port-scan        Disable port scanning
  --port-range START-END
                        Custom port range to scan (e.g., 49152-49200)
  --common-ports-only   Only scan commonly used DCOM ports (default)
  -p, --port PORT       Check a specific port only

Check Selection Options:
  --list-checks         List all available security checks and exit
  --check-all           Enable all security checks including optional ones
  --enable-check CHECK  Enable a specific check (can be used multiple times)
  --disable-check CHECK Disable a specific check (can be used multiple times)
  --only-checks CHECKS  Run only specified checks (comma-separated list)

OPC-Specific Options:
  --check-hda           Enable OPC-HDA (Historical Data Access) checks
  --check-ae            Enable OPC-AE (Alarms & Events) checks
  --check-batch         Enable OPC Batch interface checks
  --check-windows       Enable Windows service checks (WMI, SAMR, etc.)

Output Options:
  -v, --verbose         Enable verbose output with detailed information
  -q, --quiet           Quiet mode - only show security findings
  --json                Output results in JSON format
  --xml                 Output results in XML format
  --csv                 Output results in CSV format
  -o, --output FILE     Write results to file
  --min-severity LEVEL  Minimum severity level to display (default: INFO)
  --no-color            Disable colored output
  --show-passed         Show passed checks in output (default: enabled)
  --hide-passed         Hide passed checks, only show findings

Connection Options:
  -t, --timeout SECONDS Connection timeout in seconds (default: 5)
  --retry COUNT         Number of retries for failed connections (default: 1)
  --delay SECONDS       Delay between checks in seconds (default: 0)
  --source-ip IP        Source IP address to use for connections

General Options:
  -V, --version         Show version number and exit
  -h, --help            Show this help message and exit
```

### Examples

```bash
# Basic security check against an IP address
opccheck 192.168.1.100

# Verbose check against a DNS hostname
opccheck opcserver.example.com -v

# Run all available checks including optional ones
opccheck 10.0.0.50 --check-all

# Enable specific additional checks
opccheck 192.168.1.100 --enable-check opc_hda --enable-check opc_ae

# Disable specific checks
opccheck 192.168.1.100 --disable-check null_session

# Extended port scanning with custom range
opccheck 10.0.0.50 --port-range 49152-49200

# Skip port scanning, only check security settings
opccheck 192.168.1.100 --no-port-scan

# Check with extended timeout and retries for slow networks
opccheck server.local --timeout 10 --retry 3

# Output results to JSON file
opccheck 192.168.1.100 --json -o results.json

# Only show HIGH and CRITICAL findings
opccheck 192.168.1.100 --min-severity HIGH

# Show only security findings (no passed checks)
opccheck 192.168.1.100 --hide-passed

# Check a specific port
opccheck 192.168.1.100 -p 135

# Enable OPC-HDA and OPC-AE checks
opccheck 192.168.1.100 --check-hda --check-ae

# Enable Windows service enumeration checks
opccheck 192.168.1.100 --check-windows

# List all available checks
opccheck --list-checks
```

## Available Security Checks

Run `opccheck --list-checks` to see all available checks. The checks are organized by category:

### Network & Ports
| Check ID | Name | Default |
|----------|------|---------|
| dcom_ports | DCOM Port Accessibility | Yes |
| endpoint_mapper | RPC Endpoint Mapper | Yes |
| smb_signing | SMB Signing | No |
| connection_limits | Connection Limits | No |

### Authentication
| Check ID | Name | Default |
|----------|------|---------|
| authentication | OPC-DA Authentication | Yes |
| ntlm_auth | NTLM Authentication | Yes |
| null_session | Null Session Access | Yes |

### OPC-DA Interfaces
| Check ID | Name | Default |
|----------|------|---------|
| browsing | OPC Item Browsing | Yes |
| server_enumeration | OPC Server Enumeration | Yes |
| da_version | OPC-DA Version Detection | Yes |
| sync_io | Synchronous I/O Access | Yes |
| async_io | Asynchronous I/O Access | Yes |
| item_management | Item Management Access | Yes |
| group_management | Group Management Access | Yes |
| item_properties | Item Properties Access | Yes |
| callback_interface | Data Callback Interface | Yes |
| item_deadband | Item Deadband Management | No |
| public_groups | Public Groups Access | No |

### DCOM Services
| Check ID | Name | Default |
|----------|------|---------|
| remote_activation | DCOM Remote Activation | Yes |

### Security Interfaces
| Check ID | Name | Default |
|----------|------|---------|
| opc_security | OPC Security Interface | Yes |

### Other OPC Specifications
| Check ID | Name | Default |
|----------|------|---------|
| opc_hda | OPC-HDA Interface | No |
| opc_ae | OPC-AE Interface | No |
| opc_batch | OPC Batch Interface | No |
| opc_dx | OPC-DX Interface | No |
| opc_commands | OPC Commands Interface | No |

### Windows Services
| Check ID | Name | Default |
|----------|------|---------|
| wmi_dcom | WMI over DCOM | No |
| samr_access | SAM-R Protocol Access | No |
| lsa_access | LSA Protocol Access | No |
| srvsvc_access | Server Service Access | No |

## Security Checks Performed

### 1. DCOM Port Accessibility

Scans for accessible DCOM ports including:
- Port 135 (RPC Endpoint Mapper)
- Port 139 (NetBIOS)
- Port 445 (SMB)
- Port 593 (HTTP RPC Endpoint Mapper)
- Legacy dynamic ports (1024-1030)
- Modern dynamic ports (49152-49160)

### 2. RPC Endpoint Mapper

Checks if the RPC Endpoint Mapper (port 135) is accessible from the remote host. An accessible endpoint mapper can reveal information about available DCOM services.

### 3. OPC-DA Authentication

Verifies whether the OPC-DA server requires authentication:
- Tests unauthenticated/anonymous access attempts
- Identifies the authentication level required
- Detects if anonymous connections are permitted

### 4. OPC Item Browsing

Checks if the OPC item browsing interface (IOPCBrowseServerAddressSpace) is accessible:
- Determines if clients can enumerate OPC items
- Tests for browsing restrictions

### 5. DCOM Remote Activation

Checks if DCOM remote activation is enabled:
- Tests OXID Resolver accessibility
- Checks IRemUnknown2 interface access
- Identifies potential for remote COM object instantiation

### 6. OPC Server Enumeration

Checks if the IOPCServerList interface is accessible, which allows clients to enumerate available OPC servers on the target system.

### 7. OPC-DA Version Detection

Probes version-specific interfaces to detect supported OPC-DA versions:
- DA 1.0: IOPCAsyncIO interface
- DA 2.0: IOPCAsyncIO2 interface
- DA 3.0: IOPCAsyncIO3 and IOPCBrowse interfaces

### 8. Synchronous/Asynchronous I/O Access

Checks if read/write operation interfaces are accessible:
- IOPCSyncIO (direct synchronous operations)
- IOPCAsyncIO2 (asynchronous operations with callbacks)

### 9. OPC Security Interface

Checks for OPC Security specification compliance:
- IOPCSecurityNT (Windows authentication integration)
- IOPCSecurityPrivate (custom authentication)

### 10. OPC-HDA Interface (Optional)

Checks for Historical Data Access interfaces:
- IOPCHDA_Server (server interface)
- IOPCHDA_Browser (historical data browsing)
- IOPCHDA_SyncRead (read historical data)
- IOPCHDA_SyncUpdate (write/modify historical data - HIGH severity if accessible)

### 11. OPC-AE Interface (Optional)

Checks for Alarms & Events interfaces:
- IOPCEventServer (event server)
- IOPCEventSubscriptionMgt (event subscriptions)
- IOPCEventAreaBrowser (area browsing)

### 12. Null Session Access

Checks if anonymous access is allowed to Windows services:
- SAMR (user enumeration)
- LSA (security policies)
- SRVSVC (share enumeration)

## Output Format

### Console Output

The tool displays results with severity levels:
- `CRITICAL`: Issues requiring immediate attention
- `HIGH`: Significant security concerns
- `MEDIUM`: Moderate security issues
- `LOW`: Minor security concerns
- `INFO`: Informational findings

### JSON Output

When using `--json`, results are formatted as:

```json
{
  "target": "192.168.1.100",
  "resolved_ip": "192.168.1.100",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "2.0.0",
  "checks_enabled": 18,
  "results": [
    {
      "check_name": "DCOM Port Accessibility",
      "passed": false,
      "severity": "HIGH",
      "message": "Found 2 accessible DCOM port(s)",
      "details": {
        "ports": [135, 49152]
      }
    }
  ]
}
```

### XML Output

When using `--xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<opccheck_report target="192.168.1.100" resolved_ip="192.168.1.100" timestamp="2024-01-15T10:30:00Z">
  <results>
    <check name="DCOM Port Accessibility" status="fail" severity="HIGH">
      <message>Found 2 accessible DCOM port(s)</message>
      <details>
        <ports>[135, 49152]</ports>
      </details>
    </check>
  </results>
</opccheck_report>
```

## Exit Codes

- `0`: No critical or high severity issues found
- `1`: High severity issues found
- `2`: Critical severity issues found
- `130`: Interrupted by user (Ctrl+C)

## Security Considerations

**Important**: This tool is intended for authorized security testing and research only. Always obtain proper authorization before testing systems you do not own.

### Recommended Use Cases

- Security assessments of industrial control systems
- Penetration testing of OPC infrastructure (with authorization)
- Compliance verification for OPC-DA deployments
- Network security audits
- Vulnerability assessments

### Ethical Guidelines

1. Only test systems you own or have explicit written permission to test
2. Respect rate limits and avoid causing service disruptions
3. Report vulnerabilities responsibly to system owners
4. Follow applicable laws and regulations

## Understanding OPC-DA Security

### What is OPC-DA?

OPC-DA (OLE for Process Control - Data Access) is a specification for industrial automation that uses Microsoft's DCOM (Distributed Component Object Model) for communication. It's widely used in:

- SCADA systems
- Industrial control systems (ICS)
- Manufacturing execution systems
- Building automation

### Common Security Issues

1. **Unauthenticated Access**: Many OPC-DA servers allow connections without authentication
2. **Unrestricted Browsing**: Clients can often enumerate all available data items
3. **Remote Activation**: DCOM remote activation may be enabled unnecessarily
4. **Exposed Ports**: DCOM uses dynamic ports that may be exposed to untrusted networks
5. **Historical Data Access**: OPC-HDA interfaces may allow reading or modifying historical process data
6. **Null Session Vulnerabilities**: Windows services may be accessible without authentication

### Mitigation Recommendations

- Enable DCOM authentication (at minimum CONNECT level)
- Restrict DCOM access to authorized users and groups
- Use firewalls to limit access to OPC-DA servers
- Disable unnecessary interfaces and features
- Implement network segmentation for OT networks
- Consider OPC UA as a more secure alternative
- Implement the OPC Security specification
- Disable null session access on Windows systems

## Troubleshooting

### Connection Timeout

If you experience connection timeouts:
```bash
opccheck target --timeout 15 --retry 3
```

### Name Resolution Failures

Ensure the target hostname/DNS name is resolvable:
```bash
# Test resolution
nslookup opcserver.example.com

# Use IP address directly
opccheck 192.168.1.100
```

### Permission Issues

Some scans may require elevated privileges for raw socket operations:
```bash
sudo opccheck target
```

### Too Many Checks

To run only specific checks:
```bash
# Run only authentication and browsing checks
opccheck target --only-checks authentication,browsing

# Disable slow checks
opccheck target --disable-check connection_limits
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Commit your changes (`git commit -am 'Add new security check'`)
4. Push to the branch (`git push origin feature/new-check`)
5. Create a Pull Request

## License

MIT License - see LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before testing systems.

## Changelog

### Version 2.0.0

- Added 20+ new security checks for OPC-DA interfaces
- Added OPC-HDA (Historical Data Access) checks
- Added OPC-AE (Alarms & Events) checks
- Added OPC Batch interface checks
- Added Windows service enumeration checks (WMI, SAMR, LSA, SRVSVC)
- Added OPC-DA version detection (1.0, 2.0, 3.0)
- Added check selection options (--enable-check, --disable-check, --only-checks)
- Added --check-all option for comprehensive testing
- Added --list-checks to display available checks
- Added XML and CSV output formats
- Added --min-severity filtering
- Added --hide-passed option
- Added --retry and --delay connection options
- Improved OPC Security specification compliance checking
- Enhanced documentation

### Version 1.0.0

- Initial release with core OPC-DA security checks

## References

- [OPC Foundation](https://opcfoundation.org/)
- [OPC-DA Specification](https://opcfoundation.org/developer-tools/specifications-classic/data-access/)
- [OPC Security Specification](https://opcfoundation.org/developer-tools/specifications-classic/opc-security/)
- [Microsoft DCOM Documentation](https://docs.microsoft.com/en-us/windows/win32/com/component-object-model--com--portal)
- [ICS-CERT OPC Security Guidelines](https://www.cisa.gov/uscert/ics)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
