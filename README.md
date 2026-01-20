# OPCCheck - OPC-DA Security Checker

A command-line tool for security assessment of OPC-DA (OLE for Process Control - Data Access) servers. This tool performs various security checks including DCOM connectivity tests, authentication verification, and browsing capability assessment.

## Features

- **DCOM Port Scanning**: Test dynamic ports to identify accessible DCOM endpoints
- **Authentication Checks**: Verify if OPC-DA connections can be performed without authentication
- **OPC Item Browsing**: Check if clients can browse OPC items and whether restrictions are in place
- **Remote Activation Detection**: Determine if DCOM remote activation is enabled
- **OPC Server Enumeration**: Check if the IOPCServerList interface is accessible
- **Cross-Platform**: Works on Linux and macOS (no Windows dependencies)
- **JSON Output**: Export results in JSON format for integration with other tools

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

# Check an OPC-DA server by DNS name
opccheck opc.industrial.local
```

### Options

```
usage: opccheck [-h] [--scan-ports] [--no-port-scan] [--port-range START-END]
                [--common-ports-only] [-p PORT] [--check-auth] [--check-browse]
                [--check-activation] [-v] [-q] [--json] [-o FILE] [-t SECONDS]
                [-V]
                TARGET

positional arguments:
  TARGET                Target OPC-DA server (hostname, DNS name, or IP address)

Port Scanning Options:
  --scan-ports          Scan for accessible DCOM ports (default: enabled)
  --no-port-scan        Disable port scanning
  --port-range START-END
                        Custom port range to scan (e.g., 49152-49200)
  --common-ports-only   Only scan commonly used DCOM ports (default)
  -p, --port PORT       Check a specific port only

Security Check Options:
  --check-auth          Check authentication requirements (default: enabled)
  --check-browse        Check OPC item browsing capability (default: enabled)
  --check-activation    Check DCOM remote activation (default: enabled)

Output Options:
  -v, --verbose         Enable verbose output
  -q, --quiet           Quiet mode - only show findings
  --json                Output results in JSON format
  -o, --output FILE     Write results to file

Connection Options:
  -t, --timeout SECONDS Connection timeout in seconds (default: 5)

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

# Extended port scanning with custom range
opccheck 10.0.0.50 --port-range 49152-49200

# Skip port scanning, only check security settings
opccheck 192.168.1.100 --no-port-scan

# Check with extended timeout for slow networks
opccheck server.local --timeout 10

# Output results to JSON
opccheck 192.168.1.100 --json

# Save results to a file
opccheck 192.168.1.100 -o results.json

# Check a specific port
opccheck 192.168.1.100 -p 135
```

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
  "timestamp": "2024-01-15T10:30:00Z",
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

### Mitigation Recommendations

- Enable DCOM authentication (at minimum CONNECT level)
- Restrict DCOM access to authorized users and groups
- Use firewalls to limit access to OPC-DA servers
- Disable unnecessary interfaces and features
- Implement network segmentation for OT networks
- Consider OPC UA as a more secure alternative

## Troubleshooting

### Connection Timeout

If you experience connection timeouts:
```bash
opccheck target --timeout 15
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

## References

- [OPC Foundation](https://opcfoundation.org/)
- [Microsoft DCOM Documentation](https://docs.microsoft.com/en-us/windows/win32/com/component-object-model--com--portal)
- [ICS-CERT OPC Security Guidelines](https://www.cisa.gov/uscert/ics)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
