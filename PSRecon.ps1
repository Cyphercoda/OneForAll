function Get-HostSummary
{
    [CmdletBinding()]
    Param()

    Write-Host ''
    Write-Host '[*]  Host Summary' -ForegroundColor Cyan

    $HostSummary =
    @{
        'Current Username' = $env:USERNAME
        'Domain' = $env:USERDNSDOMAIN
        'Hostname' = $env:COMPUTERNAME
        'LogonServer' = $env:LOGONSERVER
        'Current User Path' = $env:SystemDrive + $env:HOMEPATH
        'Public User Path' = $env:PUBLIC
    }

    # $script:OSVersion allows the variable to be called by other functions in the script
    $script:OSVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
        $HostSummary += @{'OS Version' = $OSVersion}

    # Sort the $HostSummary hashtable alphabetically by key. '[ordered]' can't be used, as it is a PSv3+ attribute.
    $HostSummary.GetEnumerator() | Sort-Object -Property key | Format-Table -HideTableHeaders
}


function Get-HostIPAddress
{
    [CmdletBinding()]
    Param()

    Write-Host "[*] Host IP Addresses`n" -ForegroundColor Cyan

    $IPAddresses = Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' }
    $IPAddresses | Format-Table -Property IPAddress, InterfaceAlias -AutoSize
}


function Get-LocalUsers
{
    [CmdletBinding()]
    Param()

    Write-Host "`n"
    Write-Host '[*] Active Local Users' -ForegroundColor Cyan
       
    # Use Get-CimInstance instead of Get-WmiObject
    $LocalUsers = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount='True'"
    $ActiveLocalUsers = $LocalUsers | Where-Object {-not $_.Disabled}
    $ActiveLocalUsers | Format-Table -Property Name -HideTableHeaders
}


function Get-LocalAdmins
{
    [CmdletBinding()]
    Param()

    Write-Host "[*] Local Admins`n" -ForegroundColor Cyan
    
    # Use Get-CimInstance instead of Get-WmiObject
    $AdminGroup = Get-CimInstance -ClassName Win32_GroupUser | Where-Object {$_.GroupComponent -match "administrators" `
                                -and ($_.GroupComponent -match "Domain=`"$env:COMPUTERNAME`"")}

    foreach ($AdminUser in $AdminGroup)
    {
        $AdminSplit = $AdminUser.partcomponent | Out-String
        $AdminUserSplit = ((($AdminSplit.Split('=')[-1]).Substring(1)).Trim()).TrimEnd('"')
        $AdminDomainSplit = $AdminSplit.Split('"')[1]
        Write-Output "$AdminDomainSplit\$AdminUserSplit"
    }
}


function Get-NETVersions
{
    [CmdletBinding()]
    Param
    (
        [switch]
        $Defense
    )

    Write-Host "`n"
    Write-Host "[*] .NET Versions Installed`n" -ForegroundColor Cyan

    $DotNetVers = Get-ChildItem -Path C:\Windows\Microsoft.NET\Framework -Name "v*"

    foreach ($DotNetVer in $DotNetVers)
    {
        $DotNetVerFile = Get-ChildItem -Path C:\Windows\Microsoft.Net\Framework\$DotNetVer\System.dll -ErrorAction SilentlyContinue
    
        if ($DotNetVerFile)
        {
            if ($DotNetVer -eq 'v2.0.50727' -and $Defense)
            {
                    Write-Warning "$DotNetVer"
            }

            else
            {
                Write-Output "$DotNetVer"
            }
        }
    }
}    


function Get-PowerShellVersions
{
    [CmdletBinding()]
    Param
    (
        [switch]
        $Defense
    )

    Write-Host "`n"
    Write-Host "[*] PowerShell Versions Installed`n" -ForegroundColor Cyan

    $PSRegEngVers = (1..5)

    foreach ($PSRegEngVer in $PSRegEngVers)
    {      
        $PSRegEng = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PowerShell\$PSRegEngVer\PowerShellEngine -ErrorAction SilentlyContinue
        if ($PSRegEng)
        {

            if ($($PSRegEng.PowerShellVersion -eq '2.0'))
            {
                if ($Defense)
                {
                    Write-Warning "Ver: $($PSRegEng.PowerShellVersion)"
                }

                else
                {
                    Write-Output "Ver: $($PSRegEng.PowerShellVersion)"
                }
            }

            else
            {
                if ($Defense)
                {
                    Write-Output "Ver: $($PSRegEng.PowerShellVersion)"
                }

                else
                {
                    Write-Warning "Ver: $($PSRegEng.PowerShellVersion)"
                }
            }
        }
    }
}


function Get-PSExecPolicy
{
    [CmdletBinding()]
    Param()

    Write-Host "`n"
    Write-Host "[*] PowerShell Execution Policy`n" -ForegroundColor Cyan

    $PSExecPolicy = Get-ExecutionPolicy -List
    Write-Output $PSExecPolicy | Format-Table -AutoSize
    Write-Output "[!] Note: The execution policy was never meant to be used as a mitigation against malicious execution."
}


function Get-PSLogging
{
    [CmdletBinding()]
    Param
    (
        [switch]
        $Defense
    )

    Write-Host "`n"
    Write-Host "[*] PowerShell Logging Status`n" -ForegroundColor Cyan

    $PSSBL = Get-ItemProperty -Path HKLM:SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name 'EnableScriptBlockLogging' -ErrorAction SilentlyContinue
    if ($PSSBL)
    {
    
        if ($PSSBL.EnableScriptBlockLogging -eq 1)
        {
            if ($Defense)
            {
                Write-Output 'Scriptblock logging: Enabled'
            }

            else
            {
                Write-Warning 'Scriptblock logging: Enabled'
            }
        }

        elseif ($PSSBL.EnableScriptBlackLogging -eq 0)
        {
            if ($Defense)
            {
                Write-Warning 'Scriptblock logging: Disabled'
            }

            else
            {
                Write-Output 'Scriptblock logging: Disabled'
            }
        }
        
    }

    else
    {
        if ($Defense)
        {
            Write-Warning 'Scriptblock Logging: Registry key does not exist'
        }

        else
        {
            Write-Output 'Scriptblock Logging: Registry key does not exist'
        }
    }

    $PSTrans = Get-ItemProperty -Path HKLM:SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription -Name 'EnableTranscripting' -ErrorAction SilentlyContinue
    if ($PSTrans)
    {
        if ($PSTrans.EnableTranscripting -eq 1)
        {
            if ($Defense)
            {
                Write-Output 'Transcription logging: Enabled'
            }

            else
            {
                Write-Warning 'Transcription logging: Enabled'
            }
        }

        elseif ($PSTrans.EnableTranscripting -eq 0)
        {
            if ($Defense)
            {
                Write-Warning 'Transcription logging: Disabled'
            }

            else
            {
                Write-Output 'Transcription logging: Disabled'
            }
        }
    }

    else
    {
        if ($Defense)
        {
            Write-Warning 'Transcription: Registry key does not exist'
        }

        else
        {
            Write-Output 'Transcription: Registry key does not exist'
        }
    }

    $PSModLog = Get-ItemProperty -Path HKLM:SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
    if ($PSModLog)
    {
        if ($PSModLog.EnableModuleLogging -eq 1)
        {
            if ($Defense)
            {
                Write-Output 'Module logging: Enabled'
            }

            else
            {
                Write-Warning 'Module logging: Enabled'
            }
        }

        elseif ($PSModLog.EnableModuleLogging -eq 0)
        {
            if ($Defense)
            {
                Write-Warning 'Module logging: Disabled'
            }

            else
            {
                Write-Output 'Module logging: Disabled'
            }
        }
    }

    else
    {
        if ($Defense)
        {
            Write-Warning 'Module Logging: Registry key does not exist'
        }

        else
        {
            Write-Output 'Module Logging: Registry key does not exist'
        }
    }
}


function Get-SMBv1
{
    [CmdletBinding()]    
    Param
    (
        [switch]
        $Defense
    )

    Write-Host "`n"
    Write-Host "[*] Checking for SMBv1`n" -ForegroundColor Cyan

    $SMBv1Reg = (Get-ItemProperty -Path `
                    "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                    SMB1 -ErrorAction SilentlyContinue).SMB1
    
    if ($null -eq $SMBv1Reg)
    {
        if ($Defense)
        {
            Write-Warning 'The registry value for SMB1 is missing (default = 1), which means it is enabled.'
        }

        else
        {
            Write-Output 'The registry value for SMB1 is missing (default = 1), which means it is enabled.'
        }
    }
    
    elseif ($SMBv1Reg -ne 0)
    { 
        if ($Defense)
        {
            Write-Warning 'SMBv1 is Enabled'
        }

        else
        {
            Write-Output 'SMBv1 is Enabled'
        }
    }
        
    else
    {
        Write-Output 'SMBv1 is NOT enabled'
    }
}


function Get-LAPS
{
    [CmdletBinding()]
    Param
    (
        [switch]
        $Defense
    )

    Write-Host "`n"
    Write-Host "[*] LAPS Installation Status`n" -ForegroundColor Cyan

    try
    {
        $LAPS = Get-ChildItem 'C:\Program Files\LAPS\CSE\Admpwd.dll' -ErrorAction Stop
        if ($LAPS)
        {
            if ($Defense)
            {
                Write-Output "LAPS DLL discovered. LAPS might be enabled."
            }

            else
            {
                Write-Warning "LAPS DLL discovered. LAPS might be enabled."
            }
        }
    }
    
    catch
    {
        if ($Defense)
        {
            Write-Warning "LAPS is not installed."
        }

        else
        {
            Write-Output "LAPS is not installed."
        }
    }
}


function Get-AntiVirus
{
    [CmdletBinding()]
    Param
    (
        $localhost = 'localhost',

        [switch]
        $Defense
    )

    Write-Host "`n"
    Write-Host "[*] AntiVirus Products`n" -ForegroundColor Cyan
    
    $WinClientVers = @(".10.",".7.",".XP.",".Vista.")
    $WinServerVers = @(".2000.",".2003.",".2008.",".2012.",".2016.")

    if ($WinClientVers | Where-Object {$OSVersion -match $_})
    {
        $NSDirs = ('SecurityCenter','SecurityCenter2')
            foreach ($NSDir in $NSDirs)
            {
                try
                {
                    $AVProd = Get-CimInstance -Namespace root\$NSDir -ClassName AntiVirusProduct -ErrorAction Stop
                    if ($AVProd)
                    {
                        if ($Defense)
                        {
                            Write-Output "$($AVProd.displayName) is installed."
                            Write-Output "Real-Time Protection: $($AVProd.productState -eq '397312')"
                            Write-Output "Definitions Date: $($AVProd.lastUpdateTime)"
                        }

                        else
                        {
                            Write-Warning "$($AVProd.displayName) is installed."
                            Write-Warning "Real-Time Protection: $($AVProd.productState -eq '397312')"
                            Write-Warning "Definitions Date: $($AVProd.lastUpdateTime)"
                        }
                    }
                }

                catch
                {
                    if ($Defense)
                    {
                        Write-Warning 'No AV products found.'
                    }

                    else
                    {
                        Write-Output 'No AV products found.'
                    }
                }
            }
    }

    elseif ($WinServerVers | Where-Object {$OSVersion -match $_})
    {
        $Reghive = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $localhost)
        $regPathList = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

        foreach($regPath in $regPathList)
        {
            if($key = $Reghive.OpenSubKey($regPath))
            {
                if($subkeyNames = $key.GetSubKeyNames())
                {
                    foreach($subkeyName in $subkeyNames)
                    {
                        $productKey = $key.OpenSubKey($subkeyName)
                        $productName = $productKey.GetValue("DisplayName")
                        $productVersion = $productKey.GetValue("DisplayVersion")
                        $productComments = $productKey.GetValue("Comments")

                        $filters = @(".Endpoint Protection.",".AntiVirus.",".Malware.",".Defender.")
                        foreach ($filter in $filters)
                        {
                            if(($productName -match $filter) -or ($productComments -match $filter))
                            {
                                $resultObj = [PSCustomObject]@{
                                    Host = $env:COMPUTERNAME
                                    Product = $productName
                                    Version = $productVersion
                                    Comments = $productComments
                                }
                                $resultObj | Format-Table -AutoSize
                            }
                        }
                    }
                }
                $key.Close()
            }
        }
    }

    else
    {
        if ($Defense)
        {
            Write-Warning 'No AV products found.'
        }

        else
        {
            Write-Output 'No AV products found.'
        }
    }
}


function Get-MappedDrives
{
    [CmdletBinding()]
    Param()

    Write-Host "`n"
    Write-Host "[*] Mapped Drives`n" -ForegroundColor Cyan
    
    $MappedDrives = Get-CimInstance -ClassName Win32_MappedLogicalDisk
    if ($MappedDrives)
    {
        Write-Output $MappedDrives | Format-Table -Property Caption,ProviderName -AutoSize
    }
    else
    {
        Write-Output "No Mapped Drives Found"
    }
}


function Get-NetShares
{
    [CmdletBinding()]
    Param()

    Write-Host "`n"
    Write-Host "[*] Net Shares`n" -ForegroundColor Cyan
    
    $NetShares = Get-CimInstance -ClassName Win32_Share
        
    foreach ($NetShare in $NetShares)
    {
        $NetPath = $NetShare.Path

        try
        {
            $AccessRights = Get-Acl $NetPath | Select-Object -Expand Access
            $NetPath
            $AccessRights | Format-Table -Property FileSystemRights, AccessControlType, IdentityReference
        }
        catch{}
    }
}


function Get-UnattendedInstallFile
{
    [CmdletBinding()]
    Param
    (
        [switch]
        $Defense
    )

    Write-Host "`n"
    Write-Host "[*] Unattended Install File Search`n" -ForegroundColor Cyan

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $SearchLocations = @(   "c:\sysprep\sysprep.xml",
                            "c:\sysprep\sysprep.inf",
                            "c:\sysprep.inf",
                            "c:\unattend.xml",
                            "c:\unattended.xml",
                            "C:\Autounattend.xml",
                            (Join-Path $Env:WinDir "\Panther\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\Panther\unattend.xml")
                        )

    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'UnattendPath' $_
    }

    if ($Out)
    {
        if ($Defense)
        {
            Write-Warning $Out
        }

        else
        {
            Write-Output $Out    
        }
    }

    else
    {
        Write-Output "Unattended install file not found."
    }

    $ErrorActionPreference = $OrigError
}


function Get-CachedGPPPassword
{
    [CmdletBinding()]
    Param()

    Write-Host "[*] Searching for Cached GPP Passwords`n" -ForegroundColor Cyan

    $SysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL"
    $XMLFiles = Get-ChildItem -Path $SysvolPath -Recurse -Include *.xml

    foreach ($file in $XMLFiles)
    {
        $content = Get-Content $file.FullName
        if ($content -match "cpassword")
        {
            Write-Output "Potential GPP password found in: $($file.FullName)"
        }
    }
}


function Get-GPPPasswordOnDC
{
    [CmdletBinding()]
    Param()

    Write-Host "[*] Searching for GPP Passwords on Domain Controllers`n" -ForegroundColor Cyan

    $DomainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name

    foreach ($DC in $DomainControllers)
    {
        Write-Host "Checking DC: $DC" -ForegroundColor Yellow
        Invoke-Command -ComputerName $DC -ScriptBlock ${function:Get-CachedGPPPassword}
    }
}


function Get-HostChecks
{
    [CmdletBinding()]
    Param
    (
        [switch]
        $Defense,

        [switch]
        $DefenseOnly,

        [switch]
        $SkipLocalAdmins
    )

    if ($DefenseOnly)
    {
        Get-HostSummary
        Get-HostIPAddress
        Get-NETVersions -Defense
        Get-PowerShellVersions -Defense
        Get-PSLogging -Defense
        Get-SMBv1 -Defense
        Get-LAPS -Defense
        Get-AntiVirus -Defense
        Get-UnattendedInstallFile -Defense
        Get-CachedGPPPassword
    }

    else
    {
        Get-HostSummary
        Get-HostIPAddress
        Get-LocalUsers
        
        if (-Not ($SkipLocalAdmins))
        {
            Get-LocalAdmins
        }

        Get-PSExecPolicy

        if ($Defense)
        {
            Get-NETVersions -Defense
            Get-PowerShellVersions -Defense
            Get-PSLogging -Defense
            Get-SMBv1 -Defense
            Get-LAPS -Defense
            Get-AntiVirus -Defense
            Get-UnattendedInstallFile -Defense
        }

        else
        {
            Get-NETVersions
            Get-PowerShellVersions
            Get-PSLogging
            Get-SMBv1
            Get-LAPS
            Get-AntiVirus
            Get-UnattendedInstallFile
        }

        Get-MappedDrives
        Get-NetShares
        Get-CachedGPPPassword
    }
}


function Get-DomainAdmins
{
    # ... existing code ...
}


function Invoke-RemoteHostChecks
{
    [CmdletBinding()]
    Param(
        [string]$ComputerName
    )

    if (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet) {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-HostSummary
            Get-HostIPAddress
            Get-LocalUsers
            Get-LocalAdmins
            Get-PSExecPolicy
            Get-NETVersions
            Get-PowerShellVersions
            Get-PSLogging
            Get-SMBv1
            Get-LAPS
            Get-AntiVirus
            Get-MappedDrives
            Get-NetShares
            Get-UnattendedInstallFile
        }
    } else {
        Write-Host "The computer $ComputerName is not reachable."
    }
}

function Get-AntiVirusStatus
{
    [CmdletBinding()]
    Param()

    Write-Host "[*] Anti-Virus Status`n" -ForegroundColor Cyan

    $AVStatus = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct
    if ($AVStatus) {
        foreach ($av in $AVStatus) {
            Write-Output "AV Product: $($av.displayName)"
            Write-Output "Real-Time Protection: $($av.productState -eq '397312')"
            Write-Output "Definitions Date: $($av.lastUpdateTime)"
        }
    } else {
        Write-Host "No Anti-Virus products found."
    }
}

function Get-EDRProducts
{
    [CmdletBinding()]
    Param()

    Write-Host "[*] EDR Products`n" -ForegroundColor Cyan

    $EDRList = @("CarbonBlack", "Bit9", "CrowdStrike", "SentinelOne", "Cylance", "Symantec", "McAfee", "Sophos", "Trend Micro")
    $InstalledPrograms = Get-CimInstance -ClassName Win32_Product | 
                          Select-Object -Property Name, Vendor

    foreach ($EDR in $EDRList) {
        $Match = $InstalledPrograms | Where-Object { $_.Name -like "*$EDR*" -or $_.Vendor -like "*$EDR*" }
        if ($Match) {
            Write-Output "$EDR is installed"
        } else {
            Write-Output "$EDR is not installed"
        }
    }
}

function Get-SMBSigningStatus
{
    [CmdletBinding()]
    Param()

    Write-Host "[*] SMB Signing Status`n" -ForegroundColor Cyan

    $SMBClient = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    $SMBServer = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

    Write-Output "SMB Client Signing:"
    Write-Output "Enabled: $($SMBClient.EnableSecuritySignature -eq 1)"
    Write-Output "Required: $($SMBClient.RequireSecuritySignature -eq 1)"

    Write-Output "`nSMB Server Signing:"
    Write-Output "Enabled: $($SMBServer.EnableSecuritySignature -eq 1)"
    Write-Output "Required: $($SMBServer.RequireSecuritySignature -eq 1)"
}

function Invoke-PortScan
{
    [CmdletBinding()]
    Param(
        [string]$TargetHost,
        [int[]]$PortRange = 1..1024
    )

    Write-Host "[*] Port Scan on $TargetHost" -ForegroundColor Cyan

    foreach ($port in $PortRange) {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect = $tcpClient.BeginConnect($TargetHost, $port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne(100,$false)
        if($wait) {
            $tcpClient.EndConnect($connect)
            Write-Host "Port $port is open"
        }
        $tcpClient.Close()
    }
}

function Get-ProxySettings
{
    [CmdletBinding()]
    Param()

    Write-Host "[*] Proxy Settings`n" -ForegroundColor Cyan

    $ProxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    Write-Output "Proxy Enabled: $($ProxySettings.ProxyEnable)"
    Write-Output "Proxy Server: $($ProxySettings.ProxyServer)"
    Write-Output "Proxy Override: $($ProxySettings.ProxyOverride)"
    
    $AutoConfigURL = $ProxySettings.AutoConfigURL
    if ($AutoConfigURL) {
        Write-Output "Auto-Config URL: $AutoConfigURL"
    } else {
        Write-Output "No Auto-Config URL set"
    }
}

function Get-NetworkPorts
{
    [CmdletBinding()]
    Param(
        [string]$Filter = "Listening"
    )

    Write-Host "[*] $Filter Network Ports`n" -ForegroundColor Cyan

    $Ports = Get-NetTCPConnection | Where-Object State -eq $Filter
    $Ports | Format-Table -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
}

# Main execution
if ($args.Count -eq 0) {
    # If no arguments, run local checks
    Get-HostSummary
    Get-HostIPAddress
    Get-DomainAdmins
    Get-AntiVirusStatus
    Get-EDRProducts
    Get-SMBSigningStatus
    Get-ProxySettings
    Get-NetworkPorts
    
    # Check if running with elevated privileges
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($IsAdmin) {
        Get-GPPPasswordOnDC
    } else {
        Write-Host "Note: GPP Password check skipped. Run as administrator to perform this check." -ForegroundColor Yellow
    }
} elseif ($args[0] -eq "portscan") {
    # If first argument is "portscan", run port scan
    if ($args.Count -ge 4) {
        Invoke-PortScan -TargetHost $args[1] -PortRange $args[2]..$args[3]
    } else {
        Write-Host "Usage for port scan: .\host_info.ps1 portscan <TargetIP> <StartPort> <EndPort>" -ForegroundColor Yellow
    }
} else {
    # If an argument is provided, assume it's a remote computer name
    Invoke-RemoteHostChecks -ComputerName $args[0]
}