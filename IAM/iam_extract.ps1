################# Script for global uid windows extractor ######################
# AIM Of the script: Collect the local users from server and collect AD level users from current domain
# To report it in mef3 format
# =========================================================================================================================================
# Initial Author: Laxmish/Nikhil V
#
# Summary of changes:
# Version              Date        User                    Description
# --------             ----------  --------------------    -----------------------------------------------------------------------------------
# V1.0                 2022/07/20  Laxmish/Nikhil V        Initial Version
#                      2022/08/22  Laxmish/Nikhil V        Signature issue fix
#                      2022/08/22  Laxmish/Nikhil V        Parameter reporting fix
# V1.1                 2022/09/15  Laxmish/Nikhil V        Fix for local user extraction
# V1.2                 2023/04/25  Laxmish/Nikhil V        Fixing slashes in privilege and group section part
# v1.3                 2023/07/21  Laxmish/Nikhil V        Fixed enable/disable status
# v1.4                 2023/07/21  Laxmish/Nikhil V        Handled duplicate ids
# v1.5                 2023/07/21  Laxmish/Nikhil V        Handled user id reporting format
# v1.6                 2023/07/21  Laxmish/Nikhil V        Added -sid parameter
# v2.0                 2023/07/21  Laxmish/Nikhil V        Output file naming convention changed to report hostname in uppercase
# v2.0.1               2023/07/26  Laxmish/Nikhil V        Last login issue handled
# v2.0.2               2023/09/06  Laxmish/Nikhil V        Fixed the issue where description data was extracting in the group field
# v2.0.3               2023/09/27  Laxmish/Nikhil V        Added isgroup condition check for domain user for member server check
# v2.0.4               2023/11/27  Laxmish/Nikhil V        Adding the primary group in the group field in domain controller
#                      Modified from ascii format to utf8 (as per UAT tool)
# v2.0.5               2023/11/29  Laxmish/Nikhil V        Considering "Remote Desktop Users" as a privilege group
# v2.0.8               2024/05/05  Laxmish/Nikhil V        Adding all local groups in mef3
# v2.0.9               2024/05/07  Laxmish/Nikhil V        Adding all domain groups in mef3
# 2.0.10               2024/05/10  Laxmish/Nikhil          Fix for domain shortname prefix
#                      Fixed throwing error for else condition
# 2.0.11               2024/05/13  Laxmish/Nikhil V        Fix for some missing groups for ids
# 2.0.12               2024/05/20  Laxmish/Nikhil V        FQDN functionality added where the hostname can be written as FQDN format
# 2.0.13               2024/05/27  Laxmish/Nikhil V        User ids in lowercase
# 2.0.14               2024/05/27  Laxmish/Nikhil V        Parameters that are passed should be identified in log file as well as signature line
# 2.0.15               2024/05/27  Laxmish/Nikhil V        Additional comma at the privileges handled
# 2.0.16               2024/05/27  Laxmish/Nikhil V        Only local privileged groups should be extracted in the privilege field
#                      Normal groups should not be included
# 2.0.18               2024/06/14  Laxmish/Nikhil V        Handling domain prefix correction at Domain Controller & cross domain Universal Group level
# 2.0.19               2024/06/18  Laxmish/Nikhil V        Fix for primary domain prefix
# 2.0.20               2024/06/18  Laxmish/Nikhil V        Fix for domain controller duplicate users in group field
# 2.0.21               2024/06/19  Laxmish/Nikhil V        Fix for domain controller duplicate users in priv field
# 2.0.22               2024/06/19  Laxmish/Nikhil V        Fix for domain controller wrong domain prefix in priv field
# 2.0.23               2024/06/27  Laxmish/Nikhil V        Linter changes added
# 2.0.24               2024/06/27  Laxmish/Nikhil V        Additional linter changes fixed
# 2.0.25               2024/06/28  Laxmish/Nikhil V        Fixing more linter errors
# 2.0.26               2024/07/01  Laxmish/Nikhil V        Linter changes fixed
# 2.0.27               2024/07/04  Laxmish/Nikhil V        Handled script halting
# 2.0.28               2024/07/04  Laxmish/Nikhil V        Corrected signature line format, also handled standalone server execution
# 2.0.29               2024/07/05  Laxmish/Nikhil V        Enhancing script capability to support standalone workstation and standalone server
# 2.0.30               2024/07/19  Laxmish/Nikhil V        Handled issue with comma in local group reporting sections
# 2.0.31               2024/07/22  Laxmish/Nikhil V        Handled multiple commas issue in local group reporting sections
# 2.0.32               2024/07/23  Laxmish/Nikhil V        Added logic to get the complete group names of local group membership
# 2.0.33               2024/07/25  Laxmish/Nikhil V        Corrected error showing as null at description data format
# 2.0.34               2024/07/25  Laxmish/Nikhil V        Added to silently continue for error action at Get-ADUser command line
# 2.0.35               2024/07/25  Laxmish/Nikhil V        Added the logic to remove the member server temp files that have been created by script
# 2.0.36               2024/07/25  Laxmish/Nikhil V        Added the logic for Get-ADUser to use try/catch
# 2.0.37               2024/07/25  Laxmish/Nikhil V        Handled empty username field
# 2.0.38               2024/09/27  Laxmish/Nikhil V        Changing the code version as there is 0 value starting at checksum
# 2.0.39               2024/12/09  Laxmish/Nikhil V        Adding last password set for domain controller
#                                                        Mef3x format for local ids
#                                                        Mef3x format for Domain ids
# 2.0.40               2024/12/26  Laxmish/Nikhil V        Adding the last password change data of Get-LocalUser command instead of net user
#                                                        Added the last logon format same as of unix which is dd MMM yyyy when the mef3x parameter is set to #							 off_off
# 2.0.41               2024/12/27  Laxmish/Nikhil V        Changed the format of the last login date in domain controller from dd/mm/yyyy to dd MMM yyyy as #							 per unix standard
# 2.0.44	       2025/01/27  Laxmish/Nikhil V        disabled -debug parameter as default and optimised write-debug command to not write eveyrthing on #							 the powershell console and logs
# 2.0.45	       2025/01/28  Laxmish/Nikhil V	  lint errors fix for ansible
# 2.0.46	       2025/02/17  Laxmish/Nikhil V      Added kyndrylonly param on local,memberserver,domaincontroller
#							Fixed the command that was failing while extracting the local data
#							introduced -L parameter to extract only local users using -L local
#							Fixed pipeline to be reported after error code in signature line as per standard mef3 format
#							Fixed the word WINDOWS to Windows in Domain controller
# 2.0.47			2025/03/05	Laxmish/Nikhil V		Fix for EAA changes
# 2.0.48			2025/03/24	Laxmish/Nikhil V		Fixing group issue in domain controller
# 2.0.49			2025/03/28	Laxmish/Nikhil V		Fixing lastpassword change due to cpu usage suggested on ticket no:1129(ansible)
#==========================================================================================================================================


param (
    [string]$a,
    [string]$o,
    [string]$mef3x,
    [switch]$debug,
    [switch]$transcript,
    [switch]$help = $false,
    [switch]$sid,
    [switch]$fqdn,
    [switch]$allusergroup,
	[string]$L,
    [switch]$kyndrylonly
)

$DebugPreference = "continue"
#$debug = $true

# Added by nikhil 29/05/2024
# To fill the param values optimised
$param = ""
$param += if($a) { "#a:$a " } else { "" }
$param += if($debug) { "#debug " } else { "" }
$param += if($fqdn) { "#fqdn " } else { "" }
$param += if($o) { "#o:$o " } else { "" }
$param += if($transcript) { "#transcript " } else { "" }
$param += if($allusergroup) { "#allusergroup " } else { "" }
$param += if($mef3x) { "#mef3x:$mef3x " } else { "" }
$param += if($sid) { "#sid " } else { "" }
$param += if($kyndrylonly) { "#kyndrylonly " } else { "" }
$param += if($L) { "#L:$L " } else { "" }

$pathdiv = "\"

if ($transcript) {
    $transcriptfile = (Get-Location).Path + $pathdiv + "windows_powershellExtractor_log.txt"
    Start-Transcript -path $transcriptfile | Out-Null
}

$computer = hostname
$computer = $computer.ToUpper()

#optimised
$currentTime = Get-Date
$starttime = $currentTime.ToString()
$month = $currentTime.ToString("MMM", [CultureInfo]'en').ToUpper()
$year = $currentTime.ToString("yyyy")
$date = $currentTime.ToString("dd")
$starttimefinal = $currentTime.ToString("yyyy-MM-dd-HH.mm.ss")


$header = @"
UID EXTRACTOR EXECUTION - Started
START TIME: $starttime
===========================================
Wintel System Extractor
===========================================
===========================================
"@

if ($debug) {
    Write-Debug ("parameters passed: $param")
}

if ($debug) {
    Write-Debug ($header)
}

$scriptname = "iam_extract.ps1"
if ($debug) {
    Write-Debug ("SCRIPT NAME: $scriptname")
}

$scriptversion = "V2.0.49"
$isMemberServer = "False"
$isStandAloneWorkstation = "False"

if ($debug) {
    Write-Debug ("SCRIPT VERSION: $scriptversion")
}

#optimised
# Using CIM instance instead of the commented line
$Win32OS = Get-CimInstance Win32_OperatingSystem
$Win32OScaption = $Win32OS.Caption
$Win32OSversion = $Win32OS.version
$Win32OSdistributed = $Win32OS.distributed
$Win32OSosarchitecture = $Win32OS.osarchitecture
$StaticDomainName = ""

if ($debug) {
    Write-Debug ("OS CAPTION: $Win32OScaption")
}

if ($debug) {
    Write-Debug ("OS VERSION: $Win32OSversion")
}

if ($debug) {
    Write-Debug ("OS IS_CLUSTER: $Win32OSdistributed")
}

if ($debug) {
    Write-Debug ("OS Architecture: $Win32OSosarchitecture")
}


#Added by nikhil 29/05/2024
#optimised
$hostname = if($fqdn) { [System.Net.Dns]::GetHostByName($env:computerName).HostName.ToUpper() } else { $env:computerName.ToUpper() }
#optimised
$domainfqdnprefix = if($fqdn) { [System.Net.Dns]::GetHostByName($env:computerName).HostName.ToUpper() } else { $null }

if ($debug) {
    Write-Debug ("HOSTNAME: $hostname")
}

#$defaultcustomer = "Kyndryl"

if ($mef3x -ne "") {
    if ($debug) {
        Write-Debug ("mef3x value set: $mef3xval")
    }
}

#optimised
$customervalue = if($a) { $a } else { "Kyndryl" }
$csvpath = (Get-Location).Path
$orgmef = $customervalue + "_" + "$date$month$year" + "_" + $hostname + ".mef3"
$csvname = if($o) { $o } else { $orgmef }
$mef = if($o) { $o } else { Join-Path $csvpath $csvname }

#optimised
if (Test-Path -Path $mef) {
    Remove-Item -Path $mef -Force -Confirm:$false -ErrorAction Ignore
}


if ($help) {
	write-verbose -ForegroundColor Yellow "Version: 2.0.49" -verbose
	write-verbose -ForegroundColor Yellow "Usage: Wintel System Extractor -help" -verbose
	write-verbose -ForegroundColor Yellow "-------------------------------------------------------" -verbose
	write-verbose -ForegroundColor Yellow "The following input parameters shall be made available:" -verbose
	write-verbose -ForegroundColor Yellow "-------------------------------------------------------" -verbose
    write-verbose -ForegroundColor Yellow "-a: iam customer ID (Example -a:customernametest)" -verbose
    write-verbose -ForegroundColor Yellow "-Help: Displays the information about run-time parameters" -verbose
	write-verbose -ForegroundColor Yellow "-o: Name of output file (Example: -o:"C:\xyz\test.mef3")" -verbose
	write-verbose -ForegroundColor Yellow "-transcript Provides the transcript details(Example: -transcript)" -verbose
	write-verbose -ForegroundColor Yellow "-debug provides the debug details(Example to write into a file: -debug 5>logwindows.txt)" -verbose
	write-verbose -ForegroundColor Yellow "-sid will report the user ids which has s- format" -verbose
    write-verbose -ForegroundColor Yellow "-FQDN will report the user ids& Hosts with fully qualified domain name" -verbose
	write-verbose -ForegroundColor Yellow "-allusergroup will report all the user ids irrespective of the privileges" -verbose
    write-verbose -ForegroundColor Yellow "-mef3x will report last logon with different formats acoording to switch on_on , off_off,on_off" -verbose
	write-verbose -ForegroundColor Yellow "-kyndrylonly will only report kyndryl ids" -verbose
	write-verbose -ForegroundColor Yellow "-L local will only report local ids and not domain ids" -verbose
    exit
}


if ($debug) {
    Write-Debug ("Checking server type, Connecting to: $hostname")
}

# Using CIM instance instead of WMI
#optimised
$serverrole = (Get-CimInstance Win32_ComputerSystem).DomainRole

if ($serverrole -eq "0") {
	$debug = $true
    if ($debug) {
        $isStandAloneWorkstation = "True"  # In case of standalone workstation
        Write-Debug ("Standalone workstation")
    }
}

if ($serverrole -eq "1") {
	$debug = $true
    if ($debug) {
        Write-Debug ("Member Workstation")
    }
}

if ($serverrole -eq "2") {
	$debug = $true
    if ($debug) {
        $isStandAloneWorkstation = "True"  # In case of standalone server
        Write-Debug ("Standalone Server")
    }
}

if ($serverrole -eq "3") {
	$debug = $true
    if ($debug) {
        $isMemberServer = "True"  # In case of member server
        Write-Debug ("Member Server")
    }
}

if ($serverrole -eq "4") {
	#$L -ne "local"
    if ($debug) {
        Write-Debug ("Backup Domain Controller")
    }
}

if ($serverrole -eq "5") {
	#$L -ne "local"
    if ($debug) {
        Write-Debug ("Primary Domain Controller")
    }
}

if ($debug) {
    Write-Debug ("Checking domain prefixing")
}

 $domainprefix = 0

Switch ($serverrole) {
    0 { $domainprefix = 1 }
    1 { $domainprefix = 0 }
    2 { $domainprefix = 1 }
    3 { $domainprefix = 0 }
    4 { $domainprefix = 1 }
    5 { $domainprefix = 1 }
    default { $domainprefix = 1 }
}

if ($debug) {
    Write-Debug ("domain prefix-->$domainprefix")
}

$currentdomain = (Get-CimInstance Win32_ComputerSystem).Domain
if ($debug) {
    Write-Debug ("Current Domain: $currentdomain")
}

$currentusername = $env:UserName
$currentdomain = $env:Userdomain
$currentloggedinuser = "$currentdomain\$currentusername"


if ($fqdn) {
    $domainname = [System.Net.Dns]::GetHostByName($env:computerName).HostName
} else {
    $domainname = $currentdomain
}

$domainnamedc = $currentdomain  # Using this because if fqdn passed, group domain prefix also changing to fqdn

if ($debug) {
    Write-Debug ("LoggedinUser: $currentloggedinuser")
}

if ($debug) {
    Write-Debug ("================================================")
}

if ($debug) {
    Write-Debug ("Entering HealthCheck ....")
}

$env:SystemDirectory = [Environment]::SystemDirectory

function setlanguage {
    $language = chcp
    $languagecode = $language -split ":"
    $languagecode = ($languagecode[1]).Trim()

    if ($languagecode -match "437") {
        if ($debug) {
            Write-Debug ("Language of the server is English: $languagecode")
        }
    } else {
        if ($debug) {
            Write-Debug ("Language of the server is not English.")
        }
    }
}

setlanguage

function powershelladmincheck {
    if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if ($debug) {
            Write-Debug ("Powershell is launched as Administrator")
        }
    } else {
        if ($debug) {
            Write-Debug ("Powershell is not launched as Administrator")
        }
    }
}

# In case of member server, script should execute it as administrator
if ($isMemberServer -eq "True") {
    powershelladmincheck
}

function isadministrator {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().Groups.IsWellKnown('BuiltinAdministratorsSid') -eq $true) {
        if ($debug) {
            Write-Debug ("Access right is correct")
        }
    } else {
        if ($debug) {
            Write-Debug ("Access right is not correct")
        }
    }
}

# isadministrator
if ($debug) {
    Write-Debug ("Healthcheck completed...")
}

if ($debug) {
    Write-Debug ("Reading in local users, connecting to: $hostname")
}

# Function to remove mef3 file ####
function removepreviousmef3file {
    # Placeholder for function logic
}

if ($debug) {
    Write-Debug ("Processing local users start")
}

# try {
$RC = 0

#-------------------------------------------------------------------------------------------------------------
if($isMemberServer -eq "True" -or $isStandAloneWorkstation -eq "True"){

# Rewriting the command using CIM instance

    $AllLocalAccounts = Get-CimInstance -Class Win32_UserAccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'" -ErrorAction Stop

# Initialize an empty array to store objects
$Obj = @()

#$Groupvalue = @()  # Uncomment if needed for the script


	foreach ($LocalAccount in $AllLocalAccounts) {
		#kyndrylonly for local
	  if ($kyndrylonly) {

        # Set description value
        $desc_local = $LocalAccount.Description

        # Check if $a matches any of the patterns
        $patterns = @("/I/", "/K/", "/S/", "/F/", "/T/", "/E/", "/N/", "@kyndryl.com", "@Kyndryl.com", "@KYNDRYL.COM")

        # Check if $desc_local matches any of the patterns
        if ($desc_local -match $patterns[0] -or
            $desc_local -match $patterns[1] -or
            $desc_local -match $patterns[2] -or
            $desc_local -match $patterns[3] -or
            $desc_local -match $patterns[4] -or
            $desc_local -match $patterns[5] -or
	    $desc_local -match $patterns[6] -or
	    $LocalAccount.Name -match $patterns[7] -or
	    $LocalAccount.Name -match $patterns[8] -or
            $LocalAccount.Name -match $patterns[9]) {

            # Pattern match found

        } else {
            # No pattern match, continue with next iteration
            continue
        }
    }

    $Object = New-Object -TypeName PSObject

    $adsi = [ADSI]"WinNT://$hostname/$($LocalAccount.Name),user"

$adsi.Children | Where-Object { $_.Name -eq $LocalAccount.Name } | ForEach-Object {
    if (@() -ne $_.PrimaryGroupID) {
        $groups = $_.Groups() | ForEach-Object {
            $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
        }
    } else {
        $groups = ""
    }

    $groups

}

$localgroupname = ""
$localnameslist = $LocalAccount.Name
$adsi_for_local = [ADSI]"WinNT://$env:COMPUTERNAME/$localnameslist"


$adsi_for_local | Where-Object { $_.SchemaClassName -eq 'user' } | ForEach-Object {
    $localgroupname = $_.Groups() | ForEach-Object {
        $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
    }
    Write-Debug "groups before joining --> $localgroupname"
}

$localgroupname = $localgroupname -join ','

#**********************************************
$grpDictionary = 'Administrators","DB2ADMNS","ORADBA","Domain Admins","Remote Desktop Users","Enterprise Admins","Power Users","Backup Operators","Print Operators","Network Configuration Operators","DHCP Administrators","Account Operators","Pre-Windows 2000 Compatible Access X Server Operators","Group Policy Creator Owners","Schema Admins","Group Policy Owners","Enterprise Operators","Certificate Service DCOM Access","Distributed COM Users","Event Log Readers","Performance Log Users","Performance Monitor Users","All Application Packages","All Restricted Application Packages'
$priv = ""
$privSplit = $localgroupname -split ","

 foreach ($val1 in $privsplit) {

    if ($grpDictionary.Contains($val1)) {
        If ($val1 -eq "Users") {
            $val1 = ""
        }

        if ([string]::IsNullOrWhiteSpace($val1)) {
            $val1 = ""
        } else {
            if ([string]::IsNullOrWhiteSpace($priv)) {
                $priv = $val1
            } else {
                $priv = $priv + "," + $val1
            }
        }
    }
}
$lastlogin = (net user $LocalAccount.Name | findstr /B /C:"Last logon")
$lastlogin = $lastlogin.Trim("Last logon")

if ($lastlogin -eq "Never") {
    $lastlogindatefinal = ""
}
Else {
    $lastlogin = $lastlogin -replace "\?", ""
    $lastlogin = $lastlogin -split " "
    $lastlogin = $lastlogin[0]

    if ($lastlogin.contains(".")) {

        $lastlogindatefinal = $lastlogin -replace '\.', '/'
    } else {
        $lastlogindatefinal = $lastlogin -replace '\-', '/'
    }

    # Corrected date format dd/mm/yyyy on 22/09/2022
    $yearad = ""
    $lastlogin = ""
    $Datead = $lastlogindatefinal

    if ($DateArray -match "-") {
        $DateArray = $Datead -split "-"
    } else {
        $DateArray = $Datead -split "/"
    }

    if ($DateArray[0].length -eq 1) {
        $DateArray[0] = "0" + $DateArray[0]
    }

    if ($DateArray[1].length -eq 1) {
        $DateArray[1] = "0" + $DateArray[1]
    }

    if (-not [string]::IsNullOrWhiteSpace($DateArray[2])) {
        $yearad = $DateArray[2].substring(0, 4)

        if ($mef3x -eq "off_off") {
            $lastlogindatefinal = "$($DateArray[0])/$($DateArray[1])/$yearad"

            # Comment the below line if "dd MM yyyy" format is not required
            $lastlogindatefinal = [datetime]::ParseExact($lastlogindatefinal, "dd/MM/yyyy", [System.Globalization.CultureInfo]::GetCultureInfo("en-GB")).ToString("dd MMM yyyy")
        } else {
            $lastlogindatefinal = "$yearad$($DateArray[1])$($DateArray[0])"
        }
    }
}

		#new logic implemented for passwordlastset #nikhil 20/12/2024
if ($mef3x -ne "off_off") {
    $passwordlastsetnew = (Get-LocalUser -Name $LocalAccount.Name | Select-Object -ExpandProperty PasswordLastSet)
    $passwordlastsetnew = $passwordlastsetnew.Date
    $passwordlastsetnew = $passwordlastsetnew -split " "
    $passwordlastsetnew = $passwordlastsetnew[0]

    if ($debug) {
        write-debug ("the output is:$passwordlastsetnew")
    }

    if ($passwordlastsetnew -match "-") {
        $passwordlastsetnew = $passwordlastsetnew -split "-"
    } else {
        $passwordlastsetnew = $passwordlastsetnew -split "/"
    }

    if ($passwordlastsetnew[0].length -eq 1) {
        $passwordlastsetnew[0] = "0" + $passwordlastsetnew[0]
    }

    if ($passwordlastsetnew[1].length -eq 1) {
        $passwordlastsetnew[1] = "0" + $passwordlastsetnew[1]
    }

    $passwordlastsetnew = "$($passwordlastsetnew[2])$($passwordlastsetnew[1])$($passwordlastsetnew[0])"
}

if ($debug) {
    write-Debug ("local user id lastpassword set--> $passwordlastsetnew")
}
if ($debug) {
    write-Debug ("Account name--> $LocalAccount.Name")
}

write-Debug "final local group write --> $localgroupname"
try{

if ($mef3x -ne "off_off") {
	if (-not $Object.PSObject.Properties.Match('Name') -or $Object.Name -ne $LocalAccount.Name) {

    $object | Add-Member -MemberType NoteProperty -Name "Passwordlastset" -Value $passwordlastsetnew
	}
}
if (-not $Object.PSObject.Properties.Match('Name') -or $Object.Name -ne $LocalAccount.Name) {

$Object | Add-Member -MemberType NoteProperty -Name "Locallastlogin" -Value $lastlogindatefinal
$Object | Add-Member -MemberType NoteProperty -Name "LocalGroups" -Value $localgroupname
$Object | Add-Member -MemberType NoteProperty -Name "Name" -Value $LocalAccount.Name
$Object | Add-Member -MemberType NoteProperty -Name "Privilege" -Value $priv

if ($LocalAccount.Disabled -eq "True") {
    $status = "Disabled"
} else {
    $status = "Enabled"
}

$Object | Add-Member -MemberType NoteProperty -Name "Disabled" -Value $status
$Object | Add-Member -MemberType NoteProperty -Name "Description" -Value $LocalAccount.Description
$Obj += $Object
}
	}
	catch{
		Write-Error "Error occurred at local execution while adding the member to object"
	}
} #closed for the one that is opened in 447 foreach


#--------------------------------------------------------------------------------------------------------------
removepreviousmef3file

$procnum=(Get-CimInstance -class Win32_ComputerSystem).numberOfProcessors
$procspeed=(Get-CimInstance -class Win32_Processor).CurrentClockSpeed
$mem=(Get-CimInstance -class Win32_ComputerSystem).TotalPhysicalMemory
$network=(Get-CimInstance -class win32_networkadapter  -filter "netconnectionstatus =2").speed

#getting the checksum value:
$pwdlocation=(Get-Location).path
$file = "$pwdlocation\iam_extract.ps1"
$sha1 = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
$checksum=([System.BitConverter]::ToString( $sha1.ComputeHash([System.IO.File]::ReadAllBytes($file)))).Replace("-","").ToLower()
$checksumfinal1=$checksum -replace "[^0-9]" , ''
$checksumfinal=$checksumfinal1.substring(0,10)


if($L -eq 'local'){

    if ($mef3x -eq "off_off") {
        foreach ($y in $obj) {
            $customervalue + "|" + "S" + "|" + $hostname + "|" + "Windows" + "|" + $y.Name + "|" + "" + "|" + $y.Description + "|" + $y.Disabled + "|" + $y.Locallastlogin + "|" + $y.LocalGroups + "|" + $y.Privilege | Out-File $mef -Append -Encoding UTF8
        }
    }
    else {
        foreach ($y in $obj) {
            $customervalue + "|" + "S" + "|" + $hostname + "|" + "Windows" + "|" + $y.Name + "|" + "" + "|" + $y.Description + "|" + $y.Disabled + "|" + $y.Locallastlogin + "|" + $y.LocalGroups + "|" + $y.Privilege + "|" + $y.Passwordlastset | Out-File $mef -Append -Encoding UTF8
        }
    }

$endtimefinal =(Get-Date).ToString("yyyy-MM-dd-HH.mm.ss tt")
$endtimefinal = $endtimefinal -split " "
$endtimefinal = $endtimefinal[0]

    if ($g) {
        if ($mef3x -eq "off_off") {
        $notrealid = $customervalue + "|" + "S" + "|" + $hostname + "|" + "Windows" + "|" + "NOTaRealID-$G" + "|" + "" + "|" + "000/V///" + $starttimefinal + ":FN=" + $scriptname + ":VER=" + $scriptversion + ":CKSUM=" + $checksumfinal + "|" + "" + "|" + "" + "|" + $param + "### FINAL_TS=" + $endtimefinal + " " + "PROCNUM=" + $procnum + ":PROCSPEED=" + $procspeed + ":MEM=" + $mem + ":NETWORK=" + $network + "|" + $RC | Out-File $mef -Append -Encoding UTF8
        } else {
        $notrealid = $customervalue + "|" + "S" + "|" + $hostname + "|" + "Windows" + "|" + "NOTaRealID-$G" + "|" + "" + "|" + "000/V///" + $starttimefinal + ":FN=" + $scriptname + ":VER=" + $scriptversion + ":CKSUM=" + $checksumfinal + "|" + "" + "|" + "" + "|" + $param + "### FINAL_TS=" + $endtimefinal + " " + "PROCNUM=" + $procnum + ":PROCSPEED=" + $procspeed + ":MEM=" + $mem + ":NETWORK=" + $network + "|" + $RC + "|"| Out-File $mef -Append -Encoding UTF8
        }
    }
    else {
        if ($mef3x -eq "off_off") {
        $notrealid = $customervalue + "|" + "S" + "|" + $hostname + "|" + "Windows" + "|" + "NOTaRealID" + "|" + "" + "|" + "000/V///" + $starttimefinal + ":FN=" + $scriptname + ":VER=" + $scriptversion + ":CKSUM=" + $checksumfinal + "|" + "" + "|" + "" + "|" + $param + "### FINAL_TS=" + $endtimefinal + " " + "PROCNUM=" + $procnum + ":PROCSPEED=" + $procspeed + ":MEM=" + $mem + ":NETWORK=" + $network + "|" + $RC | Out-File $mef -Append -Encoding UTF8
        } else {
        $notrealid = $customervalue + "|" + "S" + "|" + $hostname + "|" + "Windows" + "|" + "NOTaRealID" + "|" + "" + "|" + "000/V///" + $starttimefinal + ":FN=" + $scriptname + ":VER=" + $scriptversion + ":CKSUM=" + $checksumfinal + "|" + "" + "|" + "" + "|" + $param + "### FINAL_TS=" + $endtimefinal + " " + "PROCNUM=" + $procnum + ":PROCSPEED=" + $procspeed + ":MEM=" + $mem + ":NETWORK=" + $network + "|" + $RC + "|"| Out-File $mef -Append -Encoding UTF8
        }
    }

	if ($debug) { Write-Debug ("Processing AD users end") }
if ($debug) { Write-Debug ("Report completed") }
if ($debug) { Write-Debug ("EXTRACTION PROCESS-Finished") }
if ($debug) { Write-Debug ("===========================================") }

$endtime = (Get-Date).ToString()
$elaspsedtime = (New-TimeSpan -Start $starttime -End $endtime)
$elaspsedtime = $elaspsedtime.TotalSeconds

if ($debug) { Write-Debug ("Time elapsed: $elaspsedtime second(s).") }
if ($debug) { Write-Debug ("===========================================") }
if ($debug) { Write-Debug ("General return code: $RC") }
if ($debug) { Write-Debug ("UID EXTRACTOR EXECUTION-Finished") }

if ($transcript) {
    Stop-Transcript | Out-Null
    # Reformat output to "notepad style"
    [string]::Join("`r`n",(Get-Content $transcriptfile)) | Out-File $transcriptfile
}
continue
}

}

#####################################################################
if ($debug) {
    Write-Debug ("member server condition details-->$isMemberServer")
}

##########################################################
if ($isMemberServer -eq "True"){
if ( $debug ) {
Write-Debug ("Processing member server Domain users starts")}

$Server = hostname
$Useriddata = New-Object System.Collections.ArrayList
[void]$useriddata.Add(@{version="1.0"})
$Domaindata = New-Object System.Collections.Generic.Dictionary"[String,String]"
Function Recursegroup ([string]$path) {
Write-Debug "entered debug funcn"
$Group= [ADSI]"$path,group"
Write-Debug "printing nested group function"
$subMembers = @($Group.psbase.Invoke("Members"))

Foreach($RMember in $subMembers){
$subPath = $RMember.GetType().InvokeMember("ADsPath", "GetProperty", $Null,  $RMember, $Null)

          $isGroup = ($RMember.GetType().InvokeMember("Class", "GetProperty", $Null,  $RMember, $Null) -eq "group")
write-verbose "nested group details = $isGroup" -verbose
If (($subPath -like "*/$Server/*")) {
                            $Type = 'Local'
                        } Else {$Type = 'Domain'}
if($isGroup){
$groupdetails=Recursegroup($subPath)
write-verbose "Nested group details-->$groupdetails" -verbose
}

if ($Type -eq "Domain"){
write-verbose "domain user-->$subPath" -verbose
$subPath=$subPath.Replace("WinNT://","")
$subPath=$subPath.Trim()
write-verbose "domain user details-->$subPath" -verbose
if(!$isGroup){
write-verbose "checking for group condition for domain user detail-->$isGroup" -verbose
if(!$Useriddata.keys.contains($subPath)){

[Void]$Useriddata.Add( @{ $subpath = $LocalGroup })
Write-debug "checking val at subpath $subPath and $LocalGroup"
#added new debug line to check the value
}
else{
	$ElementsOfKey = $Useriddata.$subpath
	if(!$ElementsOfKey.contains($LocalGroup)){
			[Void]$Useriddata.Add( @{ $subpath = $LocalGroup })
    Write-debug "adding new debug value check value--> $LocalGroup"
	}
}
} #group condition
}

}

}
#new code for reporting all members of group and users
$groups=net localgroup

foreach($line in $groups) {
  if($line.contains("*"))
  {
  $line=$line.Replace("*","")
  $line=$line.Trim()
  write-verbose "line val--$line" -verbose
  if ($grouplist -eq ""){$grouplist=$line}else{$grouplist=$line+","+$grouplist}
  }
}

write-verbose "grouplist val--$grouplist" -verbose
#*********************************************************
$grpDictionary = "Administrators","DB2ADMNS","ORADBA","Remote Desktop Users","Power Users","Backup Operators","Print Operators","Network Configuration Operators","DHCP Administrators","Account Operators","Pre-Windows 2000 Compatible Access X Server Operators","Group Policy Creator Owners","Schema Admins","Group Policy Owners","Enterprise Operators","Certificate Service DCOM Access","Distributed COM Users","Event Log Readers","Performance Log Users","Performance Monitor Users","All Application Packages","All Restricted Application Packages"

#Added by nikhil 29/05/2024
if($allusergroup){
	write-verbose "entering allusergroup" -verbose
	$grpDictionary=$grouplist+$grpDictionary
	}
write-verbose "groupdictionary val--$grouplist" -verbose
write-verbose "priv val of dictionary--$grpDictionary" -verbose
    $priv=""

    		$privSplit = $grpDictionary -split ","
foreach($val1 in $privsplit){
$LocalGroup = $val1
if ( $debug ) { Write-Debug ("Processing the groups-->$LocalGroup")}

$Group= [ADSI]"WinNT://$Server/$LocalGroup,group"
try{
$Members = @($Group.psbase.Invoke("Members"))
}
catch{
continue
}
Foreach($Member in $Members){

$Member.GetType().InvokeMember("Name", 'GetProperty', $null, $Member, $null)
 $Path = $Member.GetType().InvokeMember("ADsPath", "GetProperty", $Null, $Member, $Null)
          write-verbose "Object details = $Path" -verbose
$isGroup = ($Member.GetType().InvokeMember("Class", "GetProperty", $Null, $Member, $Null) -eq "group")
write-verbose "group details = $isGroup" -verbose
if($isGroup){
Recursegroup $Path
#new code to report all groups by LS
write-verbose "Member group details-->$path" -verbose
$temppath=$path
$temppath=$temppath.Replace("WinNT://","")
$temppath=$temppath.Trim()
}
else{
If (($Path -like "*/$Server/*")) {
                            $Type = 'Local'
                        } Else {$Type = 'Domain'}

if ($Type -eq "Domain"){
write-verbose "Member domain user-->$Path" -verbose
$path=$path.Replace("WinNT://","")
$path=$path.Trim()
$pos = $path.IndexOf("/")
$leftPart = $path.Substring(0, $pos)
 write-verbose "split details $leftPart" -verbose
$StaticDomainName=$leftPart.ToUpper()
if(!$Domaindata.keys.contains($StaticDomainName)) {
 write-verbose "domain data collection $StaticDomainName" -verbose
$Domaindata.Add($StaticDomainName,$StaticDomainName) }
write-verbose "domain details-->$StaticDomainName" -verbose

if(!$Useriddata.keys.contains($Path)){

[Void]$Useriddata.Add( @{ $path = $LocalGroup })
Write-debug "checking val at path $path and $LocalGroup"
#New code report domain users group by LS
                $MainDomainGroup=$StaticDomainName.ToUpper()+"/"+"Domain Users"
                write-debug "Main domain users1:$MainDomainGroup"
                [Void]$Useriddata.Add( @{ $path = $MainDomainGroup })
}
else{
	$ElementsOfKey = $Useriddata.$path
	if(!$ElementsOfKey.contains($LocalGroup)){
			[Void]$Useriddata.Add( @{ $path = $LocalGroup })

	}
}

}
}
}
}  #for loop close for main priv group

#checking additional users from LDAP

$fileval=(Get-Location).Path
$GroupFile=$fileval+"\"+"GroupResult.txt"
$newfile = $fileval+"\"+"alldomainusers.txt"

write-verbose "$fileval" -verbose
if (Test-Path -Path $GroupFile) { Remove-Item -Path $GroupFile -Force -Confirm:$false -ErrorAction Ignore }
if (Test-Path -Path $newfile) { Remove-Item -Path $newfile -Force -Confirm:$false -ErrorAction Ignore }



foreach($val1 in $privsplit){
$LocalGroup = $val1
if ($debug) { Write-Debug ("Processing the additional checking of groups-->$LocalGroup")}
.\Get-LocalGroupMembership.ps1 -Group $LocalGroup -Depth 100 | Out-File -FilePath .\GroupResult.txt -Append -Encoding UTF8
}
foreach ($line in [System.IO.File]::ReadLines($GroupFile))
{
write-debug "file details--->$line"
if($line.Contains("PrivGroup"))
  { #skip the line

  $LocalGroup=$line.replace("PrivGroup","")
  $LocalGroup=$LocalGroup.replace(":","")
  $LocalGroup=$LocalGroup.Trim()
  write-debug "privgroup search in file -->$LocalGroup"
  }

  #REading group details
  if($line.Contains("isGroup"))
  { #skip the line
    $isGroup=$line.replace("isGroup","")
  $isGroup=$isGroup.replace(":","")
  #nikhil using trim instead
  $isGroup=$isGroup.Trim()
  write-debug "checking is it group in file -->$isGroup"
  }

  #REading group details
  if($line.Contains("ParentGroup"))
  { #skip the line
  $ParentGroup=$line.replace("ParentGroup","")
  $ParentGroup=$ParentGroup.replace(":","")
  #nikhil using trim instead
  $ParentGroup=$ParentGroup.Trim()
  write-debug "checking ParentGroup group in file -->$ParentGroup"
  }

  #----------------------------


  if($line.Contains("UserName"))
  { #skip the line
   $Username=$line.replace("UserName","")
   $Username=$Username.replace(":","")
  $username =  $Username.Trim() #nikhil using trim instead
  write-debug "Username search domain --> $Username"

  }
   if($line.Contains("Domainname"))
  { #skip the line

  $Domainnamefirst=$line
  $Domainname=$Domainnamefirst
  write-debug "domainame first: $Domainnamefirst"

   write-debug "checking whether username able to find : $username"
    #logic for domain users
    if($username -eq "Domain Users"){

	write-debug "checking whether domainusers is found"


	write-debug "checking whether line contains domainname"

		$NewDomainname=$Domainnamefirst -split "Domainname   :"
		write-debug "data check for domain users:$NewDomainname"
		$NewDomainname = $NewDomainname[1]


            if($NewDomainname -like '*WinNT*'){
			$NewDomainname = $NewDomainname -split "WinNT://"

			$NewDomainname = $NewDomainname[1]
			$NewDomainname = $NewDomainname -split "/"
			$NewDomainname = $NewDomainname[0]
			$NewDomainname = $NewDomainname.ToUpper()
            write-verbose "the domain for domain users groups is -->$NewDomainname" -verbose
			}
			else{
			$NewDomainname = $NewDomainname.replace("{","$Null")
			$NewDomainname =  $NewDomainname -split ","
			$NewDomainname =  $NewDomainname[0]
			$NewDomainname = $NewDomainname.Trim()
			$NewDomainname = $NewDomainname.ToUpper()
			}
            write-verbose "the domain for domain users groups is -->$NewDomainname" -verbose

    write-verbose "the domain for domain users groups before starting the maincommand-->$NewDomainname" -verbose

    $AllDomainUsers = [ADSI]"WinNT://$NewDomainname"
    $AllDomainusers = $AllDomainusers.children
    $AllDomainusers = $AllDomainusers.where({$_.SchemaClassName -eq 'user'})
            $AllDomainusers = $AllDomainusers.path
			$AllDomainusers = $AllDomainusers -replace ("WinNT://","")


    $AllDomainusers | Out-File -FilePath .\alldomainusers.txt -Append -Encoding UTF8

    foreach($one in $AllDomainUsers){
    $username = $one

    $LocalGroup=$LocalGroup.replace("PrivGroup    : ","")

  write-debug "checking val at domain users before adding username $Username and $LocalGroup"


  #####adding the users to dictionary
  		if(!$Useriddata.keys.contains($Username)){
		[Void]$Useriddata.Add( @{ $Username = $LocalGroup })
				Write-debug "checking val at domain users username $Username and $LocalGroup"
                #New code report domain users group by LS
                $MainDomainGroup=$NewDomainname.ToUpper()+"/"+"Domain Users"
                write-debug "Main domain users1:$MainDomainGroup"
                [Void]$Useriddata.Add( @{ $Username = $MainDomainGroup })
        $Username=""
		}
		else{
	$ElementsOfKey = $Useriddata.$username
	if(!$ElementsOfKey.contains($LocalGroup)){
			[Void]$Useriddata.Add( @{ $username = $LocalGroup })

			Write-debug "checking val at domain users at username2 $Username and $LocalGroup"
              #New code report domain users group by LS
             $MainDomainGroup=$NewDomainname.ToUpper()+"/"+"Domain Users"
            write-debug "Main domain users2:$MainDomainGroup"
            [Void]$Useriddata.Add( @{ $Username = $MainDomainGroup })

        $Username=""

	}



}
    #Added new condition by Ls to report Domain users group 12/05/2024
	$ElementsOfKey = $Useriddata.$username
	if(!$ElementsOfKey.contains("Domain Users")){

			Write-debug "checking val at domain users at username33 $Username and $LocalGroup"
              #New code report domain users group by LS
             $MainDomainGroup=$NewDomainname.ToUpper()+"/"+"Domain Users"
            write-debug "Main domain users2:$MainDomainGroup"
            [Void]$Useriddata.Add( @{ $Username = $MainDomainGroup })

        $Username=""

	}

#########################################################################################################


  }

    }


  if ($isGroup -eq 'False'){

   $Domainname=$Domainname -replace ',','.'
  $Domainname=$Domainname -replace '\s',''
  $Domainname=$Domainname -replace "Domainname:",""
   $Domainname=$Domainname -replace $serverName,""
    $Domainname=$Domainname -replace "{",""
    $Domainname=$Domainname -replace "}",""
    $domainname = $Domainname.Trim()
    write-debug "search domain --> $Domainname"



		#############################################
      if($Domainname -like '*WinNT*'){$Username=$Domainname}else{

      #finding domain short name
	$domainname = $domainname.toupper()
	$CurrentdomainnameVal=[System.__ComObject].InvokeMember("DomainShortName", [System.Reflection.BindingFlags]::GetProperty, $null, (New-Object -ComObject "ADSystemInfo"), $null)
	$EnvDomainVal = $env:USERDomain
	$domainname=$domainname.Replace("\",".")
	$domainname=$domainname.Replace("/",".")
	if($domainname.Contains("."))
	{

	$domainnameval = $domainname.Split(".")
	foreach($val in $domainnameval){
		write-verbose "value-->$val" -verbose
		if($EnvDomainVal.Contains($val)){
		write-verbose "Found $val" -verbose
		$domainname = $env:USERDomain
        break
	}elseif($CurrentdomainnameVal.Contains($val)){
	write-verbose "DC2 Found" -verbose
	$domainname = $CurrentdomainnameVal
	break
	}
     }
  }
	else{
	$domainname= $CurrentdomainnameVal
	}
######################################################################################
	  $domainnamecheck = $domainname

	  write-verbose "Domain data -> $domainnamecheck" -verbose

$envdomain = $env:USERDomain
$envuserdomainlength = $envdomain.length

$flag=$false
$domainwithuser=""
for($i=$envuserdomainlength; $i -ge 3; $i=$i-1){
$temp = $envdomain.Substring(0,$i)

if($domainnamecheck.ToUpper().Contains($temp.ToUpper())){
    Write-debug "FOUND STRING!: $temp"
   #commented for testing by LS for domain reporting
   $flag=$true
    Break
}
else{

}
}

if($flag){
$domainwithuser=$envdomain

}
else{
$domainwithuser=$domainnamecheck

}
Write-debug "final domainwithuser -> $domainwithuser"
$username = $domainwithuser + "/" + $username
Write-debug "final usernamecheck -> $username"


      }

      $Username=$Username -replace 'WinNT://',''
      $Username=$Username -replace '//','/'
	  ####################################################


		if(!$Useriddata.keys.contains($Username)){
		[Void]$Useriddata.Add( @{ $Username = $LocalGroup })
				Write-debug "checking val at username $Username and $LocalGroup"
                Write-debug "checking val at username $Username and Parent--$domainwithuser/$ParentGroup"

                [Void]$Useriddata.Add( @{ $Username = $domainwithuser + "/"+ $ParentGroup })

                [Void]$Useriddata.Add( @{ $Username = $domainwithuser.ToUpper() + "/"+ "Domain Users" })
		}
		else{
	$ElementsOfKey = $Useriddata.$username
	if(!$ElementsOfKey.contains($LocalGroup)){
			[Void]$Useriddata.Add( @{ $username = $LocalGroup })
			Write-debug "checking val at username2 $Username and $LocalGroup"
			Write-debug "checking val at username2 $Username and Parent--$domainwithuser/$ParentGroup"

            [Void]$Useriddata.Add( @{ $Username = $domainwithuser + "/"+ $ParentGroup })

            [Void]$Useriddata.Add( @{ $Username = $domainwithuser.ToUpper() + "/"+ "Domain Users" })
	}
}

#new condition added by Ls for reporting Parenet Group for all users group condition
	$ElementsOfKey = $Useriddata.$username
	if(!$ElementsOfKey.contains($ParentGroup)){
			Write-debug "checking val at username3 $Username and Parent--$domainwithuser/$ParentGroup"

            [Void]$Useriddata.Add( @{ $Username = $domainwithuser + "/"+ $ParentGroup })

            [Void]$Useriddata.Add( @{ $Username = $domainwithuser.ToUpper() + "/"+ "Domain Users" })
	}


       $Username=""
       $LocalGroup=""
       $ParentGroup=""
        }
       }
}


foreach($keyval in $Useriddata.Keys){
$temp4 = $Useriddata.$keyval
  Write-Debug "Dictionary Values -> $keyval : $temp4"
}



#REading the values
write-verbose "Domain prefix value-->$StaticDomainName" -verbose
#reading the hash table
 write-verbose "at for loop" -verbose

if($mef3x -eq "off_off"){
 $array = "" | Select-Object Customer, Identifier, Host, OSname, uid, UICmode, uidConventionData, State, Last_logon,UserGroup, Privilege
}
else{
$array = "" | Select-Object Customer, Identifier, Host, OSname, uid, UICmode, uidConventionData, State, Last_logon,UserGroup, Privilege,Password_last
}
$i=0
$finalKeysEnd=$useriddata.keys | Sort-Object -Unique
$domainschecked=New-Object System.Collections.ArrayList
$disabledusersarray=New-Object System.Collections.ArrayList
foreach ($key in $finalkeysEnd) {
	$i=$i+1
   write-verbose "The key:-- $key and  value: $($Useriddata[$key])" -verbose
if ($key -notin $Useridverify.keys){
  		[ADSI]$groupms= "WinNT://$key,User"

  		$label=""
		$label=$groupms.description
		$Username=$key
		$lastloginms=""

		$lastlogincheck = $groupms.LastLogin.date

		if($lastlogincheck -ne ""){
			$date = $lastlogincheck
			write-debug "entering and checking date $lastlogincheck"
			$date = $date -split " "
			$DateArray = $date[0]
			$DateArray=$DateArray -split "/"

			if ($DateArray[0].length -eq "1"){
			$DateArray[0] = "0" + $DateArray[0]
			}

			if ($DateArray[2].length -eq "1"){
			$DateArray[2] = "0" + $DateArray[2]
			}

			if($mef3x -eq "off_off"){
			$lastloginms= "$($DateArray[1])/$($DateArray[0])/$($DateArray[2])"
			$lastloginms = [datetime]::ParseExact($lastloginms, "dd/MM/yyyy", [System.Globalization.CultureInfo]::GetCultureInfo("en-GB")).ToString("dd MMM yyyy")
			}
			else{
			$lastloginms= "$($DateArray[2])$($DateArray[0])$($DateArray[1])"
			}

			}
		else{

			$lastloginms=""
			}

		If($lastloginms -match "//"){
		$lastloginms = ""}

		#writing logic for passwordlastset for member server only current member server and not cross domain
		if ( $debug ) { write-debug ("checking what is in the username:$username")}
		$usertrim = $username -split("/")
		$usertrim = $usertrim[1]
		if($debug) {write-debug ("the val of trimmed user to get passlastset:$usertrim")}
		#$pass_lastset_ms = net user $usertrim /domain | find "last set"
		$pass_lastset_ms = net user $usertrim /domain | findstr /c:"last set"
		if($debug) {write-debug ("data of pass last set for ms:$pass_lastset_ms")}
		if($null -ne $pass_lastset_ms){
$pass_lastset_ms = $pass_lastset_ms -replace ("Password last set            ","")
$pass_lastset_ms = $pass_lastset_ms -split (" ")
$pass_lastset_ms = $pass_lastset_ms[0]
if($pass_lastset_ms -match "-"){
$pass_lastset_ms = $pass_lastset_ms -split "-"}
else{
$pass_lastset_ms = $pass_lastset_ms -split "/"
}
if ($pass_lastset_ms[0].length -eq "1"){
$pass_lastset_ms[0] = "0" + $pass_lastset_ms[0]
}

if ($pass_lastset_ms[1].length -eq "1"){
$pass_lastset_ms[1] = "0" + $pass_lastset_ms[1]
}
$pass_lastset_ms = "$($pass_lastset_ms[2])$($pass_lastset_ms[1])$($pass_lastset_ms[0])"
}
else{
$pass_lastset_ms = $null
}
$pass_lastset_ms


		if($null -ne $label){
		write-verbose "description-->$label" -verbose
			if($label -match '|'){
				$label = $label.replace('|','"')
			$label
			}
			else{
			$label = $label
			}
		}

		$flagging = $key.Substring(0, $key.IndexOf('/'))

		if(!$domainschecked.contains($flagging)){
			[void]$domainschecked.add($flagging)
			write-debug "checking the flag - > $flagging"
			$user_adsi = [ADSI]"WinNT://$flagging"
			$users = $user_adsi.children
			write-debug "checked all the child users"
			$DisabledUsers,$EnabledUsers = $users.where({$_.SchemaClassName -eq 'user'}).where({$_.UserFlags[0] -band 2},'Split')

			$disabledUsers = $disabledUsers.path
			$disabledUsers = $DisabledUsers -replace ("WinNT://","")

			Write-debug "checking of status of users is done"
			foreach($user in $disabledusers){
				[void]$disabledusersarray.add($user)
			}
		}


		if($disabledusersarray.contains($username)){
		write-debug "this is a disabled user"
			$userstatus="Disabled"
		}
		else{
			$userstatus="Enabled"
		write-debug "this is a enabled user"
		}


$groupvalues = ""
$privms=""



#Rewritten Code

$done=New-Object System.Collections.ArrayList

$done=New-Object System.Collections.ArrayList
foreach($key in $finalkeysEnd){

	$associatedGroups = $useriddata.$key
	$sen=""

	foreach($val in $associatedGroups){

		$sen=$sen+$val+","
	}

	if(!$done.contains($key)){

	[void]$done.add($key)

	}
}


$j=0


foreach ($key in $finalKeysEnd) {
$j=$j+1

   if($key -eq $Username){
   if([string]::IsNullOrWhiteSpace($groupvalues)){

   $groupvalues=$($Useriddata[$key])
   }

   else{
   $groupvalues=$groupvalues+","+$($Useriddata[$key])
   }


   if($grpDictionary.Contains($($Useriddata[$key])))
     {
    if([string]::IsNullOrWhiteSpace($privms)){
	$privms=$($Useriddata[$key])
	}
	else{
	$privms=$privms+","+$($Useriddata[$key])}

     }
	$sen=""
	$groupvaluesfinal=""
	if($done.contains($key)){
	foreach($val in $useriddata.$key){
	$sen=$sen+$val+","

	write-debug "concatenation of groups -> $sen"
}
		$groupvaluesfinal = $sen.substring(0, $sen.length-1)

     write-debug "before handling groups duplication :$groupvaluesfinal"

    #handling duplicate groups
     $groupvaluesfinal = ($groupvaluesfinal -split ',' | Select-object -Unique) -join ','
     write-debug "after handling groups duplication :$groupvaluesfinal"


      if($key.contains('version')){
	  continue
	  }

	  if($key -match (hostname)){
	  continue
	  }

	if( ($key -split '/' | Select-Object -Last 1) -eq "")
	{
	continue
	}

	  if($sid){

	  }
	  else{
		if($key -match ('s-')){
	  continue
	  }
	  }

#Added by nikhil 29/05/2024
write-verbose "user before fqdn param addition before mef3: $username" -verbose
if($fqdn){
$username = $username -split ("/")
$username = $domainfqdnprefix.toupper() + "/" + $username[1]
$username}
write-verbose "user before writing into mef: $username" -verbose
$username = $username


#Added by nikhil 29/05/2024
if ($groupvaluesfinal.EndsWith(',')) {
        $groupvaluesfinal = $groupvaluesfinal.Substring(0, $groupvaluesfinal.Length - 1)
    }
write-verbose "groups and privs after handling comma: $groupvaluesfinal" -verbose

#handling only privilege groups shoudl be reported in the privilege field

#Added by nikhil 29/05/2024
$fingrpDictionary = "Administrators","DB2ADMNS","ORADBA","Remote Desktop Users","Power Users","Backup Operators","Print Operators","Network Configuration Operators","DHCP Administrators","Account Operators","Pre-Windows 2000 Compatible Access X Server Operators","Group Policy Creator Owners","Schema Admins","Group Policy Owners","Enterprise Operators","Certificate Service DCOM Access","Distributed COM Users","Event Log Readers","Performance Log Users","Performance Monitor Users","All Application Packages","All Restricted Application Packages"

$finprivilege = $groupvaluesfinal
write-verbose "priv after assigning: $finprivilege" -verbose

$datagrpdic = $fingrpDictionary -split ","

$dataprivs = $finprivilege -split ","

$resultpriv = $datagrpdic | Where-Object {$_ -in $dataprivs}
$resultprivfinal = $resultpriv -join ","


if ($kyndrylonly) {
#kyndrylonly for memberserver
        # Set description value
        $desc_member = $label.tostring()

        # Check if $a matches any of the patterns
        $patterns = @("/I/", "/K/", "/S/", "/F/", "/T/", "/E/", "/N/", "@kyndryl.com", "@Kyndryl.com", "@KYNDRYL.COM")

        # Check if $desc_member matches any of the patterns
        if ($desc_member -match $patterns[0] -or
            $desc_member -match $patterns[1] -or
            $desc_member -match $patterns[2] -or
            $desc_member -match $patterns[3] -or
            $desc_member -match $patterns[4] -or
            $desc_member -match $patterns[5] -or
			$desc_member -match $patterns[6] -or
			$Username -match $patterns[7] -or
			$Username -match $patterns[8] -or
            $Username -match $patterns[9]) {

            # Pattern match found

        } else {
            # No pattern match, continue with next iteration
            continue
        }
    }




   ############################Adding data array###############################################################################
   #filling details

        $Object = New-Object -TypeName PSObject
        if($mef3x -eq "off_off"){
        $Object|Add-Member -MemberType NoteProperty -Name "Locallastlogin" -Value $lastloginms
		$Object|Add-Member -MemberType NoteProperty -Name "LocalGroups" -Value  $groupvaluesfinal
		$Object|Add-Member -MemberType NoteProperty -Name "Name" -Value  $Username
		$Object|Add-Member -MemberType NoteProperty -Name "Privilege" -Value $resultprivfinal
		$Object|Add-Member -MemberType NoteProperty -Name "Disabled" -Value $userstatus
        $Object|Add-Member -MemberType NoteProperty -Name "Description" -Value $label.tostring()
        $Obj+=$Object

}
else{

$object|Add-Member -MemberType NoteProperty -Name "Passwordlastset" -Value $pass_lastset_ms

        $Object|Add-Member -MemberType NoteProperty -Name "Locallastlogin" -Value $lastloginms
		$Object|Add-Member -MemberType NoteProperty -Name "LocalGroups" -Value  $groupvaluesfinal
		$Object|Add-Member -MemberType NoteProperty -Name "Name" -Value  $Username
		$Object|Add-Member -MemberType NoteProperty -Name "Privilege" -Value $resultprivfinal
		$Object|Add-Member -MemberType NoteProperty -Name "Disabled" -Value $userstatus
        $Object|Add-Member -MemberType NoteProperty -Name "Description" -Value $label.tostring()
        $Obj+=$Object



}
		[void]$done.add($key)


}}
 ##################################################################################################################
   }
   } #group for each end

   }
   #Added by nikhil 29/05/2024
Remove-Item -Path $GroupFile -Force -Confirm:$false -ErrorAction Ignore
Remove-Item -Path $newfile -Force -Confirm:$false -ErrorAction Ignore
   }


#**********************************************************************************************
if (($isMemberServer -eq "False") -and ($isStandAloneWorkstation -eq "False")) {
    if ($debug) { Write-Debug ("Processing AD users starts") }
    try {
        $RC = 0
        if ($debug) { Write-Debug ("the current domain is $domainname") }
        try {
            $domainAccounts = Get-ADUser -filter * -Properties Enabled, MemberOf, LastLogonDate, SamAccountName, Description, PrimaryGroup, PasswordLastSet
        }
        catch {
            Write-Error "Error occurred: $_"
        }

        $report = @()
        foreach ($account in $domainAccounts) {


      if ($debug) { Write-Debug ("UserAccount state processing wait for completion-->$account") }
	#checking for parameters kyndrylonly,customeronly,exceptcustomerid


    if ($kyndrylonly) {
	#kyndrylonly for domain controller
        # Set description value
        $desc_dc = $account.Description

        # Check if $a matches any of the patterns
        $patterns = @("/I/", "/K/", "/S/", "/F/", "/T/", "/E/", "/N/", "@kyndryl.com", "@Kyndryl.com", "@KYNDRYL.COM")

        # Check if $desc_dc matches any of the patterns
        if ($desc_dc -match $patterns[0] -or
            $desc_dc -match $patterns[1] -or
            $desc_dc -match $patterns[2] -or
            $desc_dc -match $patterns[3] -or
            $desc_dc -match $patterns[4] -or
            $desc_dc -match $patterns[5] -or
	    $desc_dc -match $patterns[6] -or
	    $account.SamAccountName -match $patterns[7] -or
	    $account.SamAccountName -match $patterns[8] -or
            $account.SamAccountName -match $patterns[9]) {

            # Pattern match found

        } else {
            # No pattern match, continue with next iteration
            continue
        }
    }

    # Determine account state (Enabled or Disabled)
    $accountstate = if ($account.Enabled) { "Enabled" } else { "Disabled" }




            # Groups details collection to report into group section
            $groups = $account.MemberOf
            $grpSplit = $groups -split ","
            $grpval = ""
            $groupcollection = ""
            $domainnamedc = ""
			$tempgroup = ""
			$single_grp = ""

            foreach ($single_grp in $grpSplit) {
                if ($single_grp -like "*DC=*") {
                    if ([string]::IsNullOrWhiteSpace($domainnamedc)) {
                        $single_grp = $single_grp.Trim()
                        $single_grp = $single_grp.replace('DC=', '')
                        $single_grp = $single_grp.replace('Builtin', '')
                        if ([string]::IsNullOrWhiteSpace($domainnamedc)) {
                            $domainnamedc = $single_grp.replace('Users', '')
                            $domainnamedc = $domainnamedc.toupper()

                        }
                    }
                }
                if ($single_grp -like "*CN=*") {
                    $single_grp = $single_grp.Trim()
                    $single_grp = $single_grp.replace('CN=', '')
                    $single_grp = $single_grp.replace('Builtin', '')
                    if ($single_grp -ne 'Users') {
                        if ($single_grp -ne "") {
                            $tempgroup = $single_grp
                            $domainnamedc = ""
                        }
                    }

                }

                if ([string]::IsNullOrWhiteSpace($grpVal)) {
                    if (![string]::IsNullOrWhiteSpace($domainnamedc)) {
			#added the below logic to check the empty value by Ls/NV 24/03/2025
			if($tempgroup -ne ""){
                        $grpVal = $domainnamedc + "/" + $tempgroup
                        $groupcollection = $tempgroup
			}
                    }
                } else {
                    if ($groupcollection.Contains($tempgroup)) { } else {
                        if (![string]::IsNullOrWhiteSpace($domainnamedc)) {
                            $grpVal = $grpVal + "," + $domainnamedc + "/" + $tempgroup
                            $groupcollection = $groupcollection + "," + $tempgroup

                        }
                    }
                }
            }

            $domainnamedc = ""
            $Primdata = $account.PrimaryGroup
            $PrimgrpSplit = $Primdata -split ","
            foreach ($Rval in $PrimgrpSplit) {
                if ($Rval -like "*DC=*") {
                    # New logic by LS for primary domain name prefix:
                    if ([string]::IsNullOrWhiteSpace($domainnamedc)) {
                        $Rval = $Rval.Trim()
                        $Rval = $Rval.replace('DC=', '')
                        $Rval = $Rval.replace('Builtin', '')
                        if ([string]::IsNullOrWhiteSpace($domainnamedc)) {
                            $domainnamedc = $Rval.replace('Users', '')
                            $domainnamedc = $domainnamedc.toupper()
                        }
                    }
                }
            }

            if ($primdata -ne "") {
                $PrimaryGroupdata = $primdata.Substring(0, $primdata.IndexOf(','))
                $PrimaryGroupdata = $PrimaryGroupdata.replace("CN=", "")
                $PrimaryGroupdata = $domainnamedc + "/" + $PrimaryGroupdata
            } else {
                $PrimaryGroupdata = $null
            }

            if (($grpval -ne "") -and ($PrimaryGroupdata -ne "")) {
                $ModifiedGroupdata = $grpval + "," + $PrimaryGroupdata
            } elseif (($grpval -ne "") -and ($PrimaryGroupdata -eq "")) {
                $ModifiedGroupdata = $grpval
            } elseif (($grpval -eq "") -and ($PrimaryGroupdata -ne "")) {
                $ModifiedGroupdata = $PrimaryGroupdata
            } else {
                $ModifiedGroupdata = $null
            }

            $grpDictionary = 'Administrators", "Domain Admins", "Enterprise Admins", "Remote Desktop Users", "Power Users", "Backup Operators", "Print Operators", "Network Configuration Operators", "DHCP Administrators", "Account Operators", "Pre-Windows 2000 Compatible Access X Server Operators", "Group Policy Creator Owners", "Schema Admins", "Group Policy Owners", "Enterprise Operators", "Certificate Service DCOM Access", "Distributed COM Users", "Event Log Readers", "Performance Log Users", "Performance Monitor Users", "All Application Packages", "All Restricted Application Packages'
            $priv = ""

            # Logic changed by LS/Nik on 19/06/2024 for wrong domain prefix
            $privSplit = $ModifiedGroupdata -split ","
            foreach ($val1 in $privSplit) {
                $checkval = $val1 -split "/"

                if ($grpDictionary.contains($checkval[1])) {
                    if (![string]::IsNullOrWhiteSpace($checkval[1])) {
                        if ([string]::IsNullOrWhiteSpace($priv)) {
                            $priv = $val1
                        } else {
                            $priv = $priv + "," + $val1
                        }
                    }
                }
            }

            $yearad = ""
            $lastlogin = ""
            $Datead = $account.LastLogonDate
            $DateArray = $Datead -split "/"
            if (-not [string]::IsNullOrWhiteSpace($DateArray[2])) {
                $yearad = $DateArray[2].substring(0, 4)
                If ($mef3x -eq "off_off") {
                    $lastlogin = "$($DateArray[1])/$($DateArray[0])/$yearad"
                    $lastlogin = [datetime]::ParseExact($lastlogin, "dd/MM/yyyy", [System.Globalization.CultureInfo]::GetCultureInfo("en-GB")).ToString("dd MMM yyyy")
                } else {
                    $lastlogin = "$yearad$($DateArray[0])$($DateArray[1])"
                }
            }
            # Logic for password last set
            $passlastset = $account.PasswordLastSet

            if ($passlastset -ne "") {
                $passlastset = $passlastset -split " "
                $passlastset = $passlastset[0]
                $Datead = $passlastset
                $DateArray = $Datead -split "/"
                if (-not [string]::IsNullOrWhiteSpace($DateArray[2])) {
                    $yearad = $DateArray[2].substring(0, 4)
                    If ($mef3x -eq "off_off") {
                        $passlastset = "$($DateArray[1])/$($DateArray[0])/$yearad"
                    } else {
                        $passlastset = "$yearad$($DateArray[0])$($DateArray[1])"
                    }
               }
            } else {
                $passlastset = ""
            }


            if ($mef3x -eq "off_off") {
                $array = "" | Select-Object Customer, Identifier, Host, OSname, uid, UICmode, uidConventionData, State, Last_logon, UserGroup, Privilege
            } else {
                $array = "" | Select-Object Customer, Identifier, Host, OSname, uid, UICmode, uidConventionData, State, Last_logon, UserGroup, Privilege, Password_last
            }

            if ($account.SamAccountName.contains("$")) {
                if ($debug) { Write-Debug ("User name contains $, skipping the value $account.SamAccountName") }
            } else {
                $array.Customer = $customervalue
                $array.Identifier = "S"
                $array.Host = $hostname
                $array.OSname = "Windows" #changed from WINDOWS to Windows
                $array.uid = if ($domainprefix -eq 0) { "$domainname/$($account.SamAccountName)" } else { $account.SamAccountName }


                $array.UICmode = ""
                # Changes done by LS/Nik for handling | in description on 14/06/2
                $array.uidConventionData = if (![string]::IsNullOrWhiteSpace($account.Description)) { $account.Description.Replace('|', '"') } else { $null }


                $array.State = $accountstate
                $array.Last_logon = $lastlogin
                # New changes by LS/Nik
                $ModifiedGroupdata = ($ModifiedGroupdata -split ',' | Select-Object -Unique) -join ','
                $array.UserGroup = $ModifiedGroupdata
                # New changes by LS/Nik on 19/06
                $privData = ($priv -split ',' | Select-Object -Unique) -join ','
                $array.Privilege = $privData

                # Adding last password change
                if ($mef3x -eq 'off_off') {
                } else {
                    $array.Password_last = $passlastset
                }
                if ($debug) { Write-Debug ("Arranging Data and writing into mef3 for the user completed-->$account") }
                $report += ($array | ConvertTo-Csv -Delimiter "|" -NoTypeInformation).replace("""", "") | Select-Object -Skip 1
            }
        }

        $report | Out-File $mef -Append -Encoding UTF8
    }
    catch {
        if ($debug) { Write-Debug ("ERROR AT AD LEVEL Extraction") }
        $RC = 2
    }
}
 #closing bracket if member server false

 #processor details and checksum for DC
 $procnum=(Get-CimInstance -class Win32_ComputerSystem).numberOfProcessors
$procspeed=(Get-CimInstance -class Win32_Processor).CurrentClockSpeed
$mem=(Get-CimInstance -class Win32_ComputerSystem).TotalPhysicalMemory
$network=(Get-CimInstance -class win32_networkadapter  -filter "netconnectionstatus =2").speed

#getting the checksum value:
$pwdlocation=(Get-Location).path
$file = "$pwdlocation\iam_extract.ps1"
$sha1 = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
$checksum=([System.BitConverter]::ToString( $sha1.ComputeHash([System.IO.File]::ReadAllBytes($file)))).Replace("-","").ToLower()
$checksumfinal1=$checksum -replace "[^0-9]" , ''
$checksumfinal=$checksumfinal1.substring(0,10)


if ($RC -ne 2) {

    if ($mef3x -eq "off_off") {
        foreach ($y in $obj) {
            $customervalue + "|" + "S" + "|" + $hostname + "|" + "Windows" + "|" + $y.Name + "|" + "" + "|" + $y.Description + "|" + $y.Disabled + "|" + $y.Locallastlogin + "|" + $y.LocalGroups + "|" + $y.Privilege | Out-File $mef -Append -Encoding UTF8
        }
    }
    else {
        foreach ($y in $obj) {
            $customervalue + "|" + "S" + "|" + $hostname + "|" + "Windows" + "|" + $y.Name + "|" + "" + "|" + $y.Description + "|" + $y.Disabled + "|" + $y.Locallastlogin + "|" + $y.LocalGroups + "|" + $y.Privilege + "|" + $y.Passwordlastset | Out-File $mef -Append -Encoding UTF8
        }
    }

$endtimefinal =(Get-Date).ToString("yyyy-MM-dd-HH.mm.ss tt")
$endtimefinal = $endtimefinal -split " "
$endtimefinal = $endtimefinal[0]

    if ($g) {
        if ($mef3x -eq "off_off") {
        $notrealid = $customervalue + "|" + "S" + "|" + $hostname + "|" + "Windows" + "|" + "NOTaRealID-$G" + "|" + "" + "|" + "000/V///" + $starttimefinal + ":FN=" + $scriptname + ":VER=" + $scriptversion + ":CKSUM=" + $checksumfinal + "|" + "" + "|" + "" + "|" + $param + "### FINAL_TS=" + $endtimefinal + " " + "PROCNUM=" + $procnum + ":PROCSPEED=" + $procspeed + ":MEM=" + $mem + ":NETWORK=" + $network + "|" + $RC | Out-File $mef -Append -Encoding UTF8
        } else {
        $notrealid = $customervalue + "|" + "S" + "|" + $hostname + "|" + "Windows" + "|" + "NOTaRealID-$G" + "|" + "" + "|" + "000/V///" + $starttimefinal + ":FN=" + $scriptname + ":VER=" + $scriptversion + ":CKSUM=" + $checksumfinal + "|" + "" + "|" + "" + "|" + $param + "### FINAL_TS=" + $endtimefinal + " " + "PROCNUM=" + $procnum + ":PROCSPEED=" + $procspeed + ":MEM=" + $mem + ":NETWORK=" + $network + "|" + $RC + "|"| Out-File $mef -Append -Encoding UTF8
        }
    }
    else {
        if ($mef3x -eq "off_off") {
        $notrealid = $customervalue + "|" + "S" + "|" + $hostname + "|" + "Windows" + "|" + "NOTaRealID" + "|" + "" + "|" + "000/V///" + $starttimefinal + ":FN=" + $scriptname + ":VER=" + $scriptversion + ":CKSUM=" + $checksumfinal + "|" + "" + "|" + "" + "|" + $param + "### FINAL_TS=" + $endtimefinal + " " + "PROCNUM=" + $procnum + ":PROCSPEED=" + $procspeed + ":MEM=" + $mem + ":NETWORK=" + $network + "|" + $RC | Out-File $mef -Append -Encoding UTF8
        } else {
        $notrealid = $customervalue + "|" + "S" + "|" + $hostname + "|" + "Windows" + "|" + "NOTaRealID" + "|" + "" + "|" + "000/V///" + $starttimefinal + ":FN=" + $scriptname + ":VER=" + $scriptversion + ":CKSUM=" + $checksumfinal + "|" + "" + "|" + "" + "|" + $param + "### FINAL_TS=" + $endtimefinal + " " + "PROCNUM=" + $procnum + ":PROCSPEED=" + $procspeed + ":MEM=" + $mem + ":NETWORK=" + $network + "|" + $RC + "|"| Out-File $mef -Append -Encoding UTF8
        }
    }
}
else {
    Remove-Item -Path $mef -Force -Confirm:$false -ErrorAction Ignore
}

$notrealid
if ($debug) { Write-Debug ("Processing AD users end") }
if ($debug) { Write-Debug ("Report completed") }
if ($debug) { Write-Debug ("EXTRACTION PROCESS-Finished") }
if ($debug) { Write-Debug ("===========================================") }

$endtime = (Get-Date).ToString()
$elaspsedtime = (New-TimeSpan -Start $starttime -End $endtime)
$elaspsedtime = $elaspsedtime.TotalSeconds

if ($debug) { Write-Debug ("Time elapsed: $elaspsedtime second(s).") }
if ($debug) { Write-Debug ("===========================================") }
if ($debug) { Write-Debug ("General return code: $RC") }
if ($debug) { Write-Debug ("UID EXTRACTOR EXECUTION-Finished") }

if ($transcript) {
    Stop-Transcript | Out-Null
    # Reformat output to "notepad style"
    [string]::Join("`r`n",(Get-Content $transcriptfile)) | Out-File $transcriptfile
}

