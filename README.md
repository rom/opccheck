# OPCCheck - OPC Security Checker

A command-line tool for security assessment of OPC-DA (OLE for Process Control - Data Access) and OPC-UA (Unified Architecture) servers. This tool performs various security checks including DCOM connectivity tests, authentication verification, browsing capability assessment, and **CVE vulnerability detection**.

## Features

- **DCOM Port Scanning**: Test dynamic ports to identify accessible DCOM endpoints
- **Authentication Checks**: Verify if OPC connections can be performed without authentication
- **OPC Item Browsing**: Check if clients can browse OPC items and whether restrictions are in place
- **Remote Activation Detection**: Determine if DCOM remote activation is enabled
- **OPC Server Enumeration**: Check if the IOPCServerList interface is accessible
- **CVE Vulnerability Checks**: Detect known vulnerabilities in OPC-DA and OPC-UA implementations
- **Cross-Platform**: Works on Linux and macOS (no Windows dependencies)
- **JSON Output**: Export results in JSON format for integration with other tools

## CVE Vulnerability Detection

### Supported CVE Checks

#### OPC-DA Vulnerabilities

| CVE ID | Name | Severity | CVSS |
|--------|------|----------|------|
| CVE-2021-26414 | Windows DCOM Security Hardening Bypass | HIGH | 6.5 |
| CVE-2018-1285 | AADvance OPC-DA Server log4net Vulnerability | CRITICAL | 9.8 |
| CVE-2006-0743 | Format String Vulnerability in OPC-DA Products | HIGH | 7.5 |

#### OPC-UA Vulnerabilities

| CVE ID | Name | Severity | CVSS |
|--------|------|----------|------|
| CVE-2024-42513 | Authentication Bypass on HTTPS Endpoints | HIGH | 8.6 |
| CVE-2024-45526 | Resource Exhaustion in .NET Standard Stack | MEDIUM | 5.3 |
| CVE-2024-33862 | Buffer Management DoS Vulnerability | HIGH | 7.5 |
| CVE-2019-19135 | Weak Randomness Credential Reuse | MEDIUM | 5.9 |
| CVE-2018-7559 | Private Key Exposure via Crafted Tokens | CRITICAL | 9.1 |
| CVE-2022-37012 | DoS via Crafted Messages | HIGH | 7.5 |
| CVE-2022-37013 | Infinite Loop with Crafted Certificates | HIGH | 7.5 |

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
# Full security assessment including CVE checks
opccheck 192.168.1.100

# Check an OPC server by hostname
opccheck opcserver.example.com

# List all supported CVE checks
opccheck --list-cves
```

### CVE-Specific Usage

```bash
# Check specific CVEs only
opccheck 192.168.1.100 --cve CVE-2021-26414 --cve CVE-2024-42513

# Only run OPC-DA CVE checks
opccheck 192.168.1.100 --opcda-cves-only

# Only run OPC-UA CVE checks
opccheck 192.168.1.100 --opcua-cves-only

# Show detailed CVE information with POC output
opccheck 192.168.1.100 -v --cve-details

# Skip CVE checks, only general security assessment
opccheck 192.168.1.100 --no-cve-checks
```

### Options

```
usage: opccheck [-h] [--scan-ports] [--no-port-scan] [--port-range START-END]
                [--common-ports-only] [-p PORT] [--check-auth] [--check-browse]
                [--check-activation] [--check-cves] [--no-cve-checks]
                [--opcda-cves-only] [--opcua-cves-only] [--cve CVE-ID]
                [--list-cves] [--cve-details] [-v] [-q] [--json] [-o FILE]
                [-t SECONDS] [-V]
                TARGET

positional arguments:
  TARGET                Target OPC server (hostname, DNS name, or IP address)

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

CVE Vulnerability Check Options:
  --check-cves          Run CVE vulnerability checks (default: enabled)
  --no-cve-checks       Disable CVE vulnerability checks
  --opcda-cves-only     Only run OPC-DA CVE checks (skip OPC-UA checks)
  --opcua-cves-only     Only run OPC-UA CVE checks (skip OPC-DA checks)
  --cve CVE-ID          Check specific CVE(s) only (can be used multiple times)
  --list-cves           List all supported CVE checks and exit
  --cve-details         Show detailed CVE information including POC output

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
# Full security assessment against an IP address
opccheck 192.168.1.100

# Verbose check with detailed CVE POC output
opccheck opcserver.example.com -v --cve-details

# Check specific vulnerabilities only
opccheck 10.0.0.50 --cve CVE-2021-26414 --cve CVE-2024-42513

# OPC-DA CVE checks only
opccheck 192.168.1.100 --opcda-cves-only

# OPC-UA CVE checks only
opccheck 192.168.1.100 --opcua-cves-only

# Skip CVE checks
opccheck 192.168.1.100 --no-cve-checks

# Output results to JSON
opccheck 192.168.1.100 --json

# Save results to a file
opccheck 192.168.1.100 -o results.json

# Extended port scanning with custom range
opccheck 10.0.0.50 --port-range 49152-49200

# Check with extended timeout for slow networks
opccheck server.local --timeout 10
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

Checks if the RPC Endpoint Mapper (port 135) is accessible from the remote host.

### 3. OPC-DA Authentication

Verifies whether the OPC-DA server requires authentication:
- Tests unauthenticated/anonymous access attempts
- Identifies the authentication level required

### 4. OPC Item Browsing

Checks if the OPC item browsing interface (IOPCBrowseServerAddressSpace) is accessible.

### 5. DCOM Remote Activation

Checks if DCOM remote activation is enabled:
- Tests OXID Resolver accessibility
- Checks IRemUnknown2 interface access

### 6. OPC Server Enumeration

Checks if the IOPCServerList interface is accessible.

### 7. CVE Vulnerability Detection

#### CVE-2021-26414: DCOM Security Hardening Bypass
- **Severity**: HIGH
- **Detection**: Tests DCOM authentication level requirements
- **Impact**: Affects all OPC-DA communication since OPC-DA relies entirely on DCOM

#### CVE-2018-1285: AADvance OPC-DA Server Vulnerability
- **Severity**: CRITICAL
- **Detection**: Checks for vulnerable log4net configurations
- **Impact**: Remote code execution through malicious serialized data

#### CVE-2006-0743: Format String Vulnerability
- **Severity**: HIGH
- **Detection**: Tests for potential format string handling issues
- **Impact**: Remote code execution via format string specifiers

#### CVE-2024-42513: OPC-UA HTTPS Authentication Bypass
- **Severity**: HIGH
- **Detection**: Tests HTTPS endpoint security configuration
- **Impact**: Unauthorized access to OPC-UA endpoints

#### CVE-2024-45526: Resource Exhaustion
- **Severity**: MEDIUM
- **Detection**: Tests for rate limiting and resource controls
- **Impact**: Performance degradation through resource exhaustion

#### CVE-2024-33862: Buffer Management DoS
- **Severity**: HIGH
- **Detection**: Tests buffer handling with edge-case sizes
- **Impact**: Memory exhaustion leading to denial of service

#### CVE-2019-19135: Weak Randomness
- **Severity**: MEDIUM
- **Detection**: Analyzes random values for weakness patterns
- **Impact**: Credential reuse through predictable values

#### CVE-2018-7559: Private Key Exposure
- **Severity**: CRITICAL
- **Detection**: Tests security policy and error handling
- **Impact**: Server private key exposure through crafted tokens

#### CVE-2022-37012: DoS via Crafted Messages
- **Severity**: HIGH
- **Detection**: Tests message handling with crafted structures
- **Impact**: Denial of service through crafted messages

#### CVE-2022-37013: Infinite Loop DoS
- **Severity**: HIGH
- **Detection**: Tests certificate parsing with edge cases
- **Impact**: Infinite loop causing denial of service

## Output Format

### Console Output

The tool displays results with severity levels:
- `CRITICAL`: Issues requiring immediate attention
- `HIGH`: Significant security concerns
- `MEDIUM`: Moderate security issues
- `LOW`: Minor security concerns
- `INFO`: Informational findings

CVE results include confidence levels:
- `HIGH`: Strong evidence of vulnerability
- `MEDIUM`: Moderate indicators detected
- `LOW`: Potential vulnerability, manual verification recommended

### JSON Output

When using `--json`, results include both general security checks and CVE results:

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
      "details": {"ports": [135, 49152]}
    }
  ],
  "cve_results": [
    {
      "cve_id": "CVE-2021-26414",
      "name": "Windows DCOM Security Hardening",
      "vulnerable": true,
      "severity": "HIGH",
      "confidence": "HIGH",
      "cvss": 6.5,
      "evidence": ["DCOM accepts unauthenticated RPC BIND requests"],
      "poc_output": "POC Step 1: Sent RPC BIND...",
      "remediation": "Apply Microsoft security update KB5004442..."
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
- Compliance verification for OPC deployments
- Network security audits
- Vulnerability assessments
- CVE verification and remediation validation

### Ethical Guidelines

1. Only test systems you own or have explicit written permission to test
2. Respect rate limits and avoid causing service disruptions
3. Report vulnerabilities responsibly to system owners
4. Follow applicable laws and regulations

## Understanding OPC Security

### What is OPC-DA?

OPC-DA (OLE for Process Control - Data Access) is a specification for industrial automation that uses Microsoft's DCOM for communication. Widely used in SCADA systems, ICS, and manufacturing.

### What is OPC-UA?

OPC-UA (Unified Architecture) is the modern, platform-independent successor to OPC-DA. It provides improved security features including encryption and authentication, but implementations may still have vulnerabilities.

### Common Security Issues

1. **Unauthenticated Access**: OPC servers allowing connections without authentication
2. **DCOM Vulnerabilities**: Windows DCOM configuration weaknesses
3. **Protocol Implementation Flaws**: Buffer overflows, resource exhaustion
4. **Weak Cryptography**: Insufficient encryption or random number generation
5. **Certificate Handling Issues**: Improper validation leading to DoS or bypass

### Mitigation Recommendations

- Apply all security patches (especially KB5004442 for DCOM hardening)
- Enable authentication at PACKET_INTEGRITY level or higher
- Implement network segmentation for OT networks
- Use firewalls to limit OPC server access
- Consider migrating from OPC-DA to OPC-UA with proper security configuration
- Regularly assess and update OPC server software
- Monitor for and respond to CVE announcements affecting OPC products

## Troubleshooting

### Connection Timeout

```bash
opccheck target --timeout 15
```

### Name Resolution Failures

```bash
# Test resolution
nslookup opcserver.example.com

# Use IP address directly
opccheck 192.168.1.100
```

### Permission Issues

Some scans may require elevated privileges:
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
- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
- [OPC UA Security Analysis](https://opcfoundation.org/security/)
