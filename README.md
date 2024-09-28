PSRecon - PowerShell Reconnaissance Script

PSRecon is a comprehensive PowerShell-based tool designed for performing reconnaissance and enumeration on Windows systems. It is intended for use by security professionals, system administrators, and penetration testers to gather detailed system information, identify misconfigurations, and check for potential security weaknesses. This tool is particularly useful during the information-gathering phase of an internal penetration test or during system audits.
Features:

    Host Information Collection: Gathers essential host details such as current username, domain, hostname, logon server, OS version, and user paths.
    Network Information: Retrieves IP addresses, network shares, and mapped drives, providing insights into the network configuration and connected resources.
    User Enumeration: Identifies local users, active users, and members of the local Administrators group.
    PowerShell & .NET Version Checks: Enumerates installed PowerShell and .NET Framework versions to identify potential vulnerabilities.
    SMBv1 Status: Detects whether the SMBv1 protocol, known for security risks, is enabled.
    Anti-Virus & EDR Product Checks: Gathers information on installed anti-virus and EDR products, including real-time protection status and virus definitions.
    PowerShell Logging & Execution Policy: Checks PowerShell logging configuration (ScriptBlock, Transcription, Module logging) and execution policy settings.
    Group Policy Preference (GPP) Password Retrieval: Searches for cached GPP passwords that could be exploited if misconfigured.
    LAPS Status: Detects if the Local Administrator Password Solution (LAPS) is installed.
    SMB Signing: Inspects SMB signing configurations for enhanced network security.
    Remote Execution: Allows running various checks on remote hosts via PowerShell Remoting, ideal for domain-wide assessments.
    Proxy Settings & Network Ports: Retrieves system proxy settings and provides a filtered list of listening and established network ports.
    Port Scanning: A built-in port scanner (stripped-down version of Nmap) for scanning open TCP ports on target hosts.

Usage:

This script can be run on local or remote Windows systems to gather detailed reconnaissance information. It is particularly suited for the following use cases:

    Internal Penetration Testing: Quickly gather system details and check for common vulnerabilities or misconfigurations.
    System Auditing: Use the script for auditing Windows systems to ensure security settings are correctly configured.
    Incident Response: Run the script as part of incident response to gather information on a potentially compromised system.

Prerequisites:

    PowerShell: The script is compatible with PowerShell 2.0 and later, though certain functions may require PowerShell 3.0+ for full functionality.
    Active Directory Module: Some functions (e.g., domain controller enumeration) require the Active Directory module to be installed and imported.
    Administrative Privileges: Certain checks (e.g., SMB, user enumeration) may require administrative access to run properly.
