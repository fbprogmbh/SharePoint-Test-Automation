<#
Copyright (c) 2017, FB Pro GmbH, Germany
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>

<#

    Author(s):        Dennis Esly
    Date:             06/01/2017
    Last change:      10/23/2017
    Version:          0.7

#>

if ((Get-Module -List ActiveDirectory) -and !(Get-Module ActiveDirectory))
{
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
}

#if ( -not (Get-PSSnapin *Sharepoint*) -and (Get-PSsnapin -registered Microsoft.SharePoint.PowerShell))
#{
    Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
#}

# Load settings from setting file
$ConfigFile = Import-LocalizedData -FileName Settings.psd1


# Set the path and name of standard log file to path and name configured in settings
$LogPath = $ConfigFile.Settings.LogFilePath
$LogName = (Get-date -Format "yyyyMMdd")+"_"+$ConfigFile.Settings.LogFileName


# Helper functions
# ----------------
<#

 Some functions used in other functions in this module.

#>

function Get-OperatingSystemInfo
{
<#
.Synopsis
   Gets a bunch of system information.
.DESCRIPTION
   Gets a bunch of system information like free RAM, free disk space, OS version etc.
#>

    Get-CimInstance Win32_OperatingSystem | select *
}

function Get-SystemStartupTime
{
<#
.Synopsis
   Gets the time of last system start up.
.DESCRIPTION
   Looks up for the last system startup by checking the event log for id 6005.
.EXAMPLE
   PS C:\Get-SystemStartupTime
   
   Freitag, 30. Dezember 2016 09:03:08
#>
   
    # Get log record with id 12 of source kernel general and return time
    Get-winevent -FilterHashtable @{Logname='System'; ProviderName='Microsoft-Windows-Kernel-General'; ID=12} -MaxEvents 1 | select @{label='TimeCreated';expression={$_.TimeCreated.ToString("yyyy-M-d HH:mm:ss")}} -ExpandProperty TimeCreated

}

function Get-LocalAdmins
{
<#
.Synopsis
   Gets all users in local group "Administrators".
.DESCRIPTION
   Gets all users in local group "Administrators". Local groups inside are not recursively resolved into their users. Groupnames will be placed in result as if they were users.
   Active Directory groups on the other hand are recursively resolved for other their users and maybe other groups inside.  
.OUTPUTS
    SamAccountNames of users
#>

    $Computer = $env:COMPUTERNAME

    $ADSIComputer = [ADSI]("WinNT://$Computer,computer")

    try 
    {
        $group = $ADSIComputer.psbase.children.find('Administrators', 'Group')
    }
    catch
    {
        try 
        {
            $group = $ADSIComputer.psbase.children.find('Administratoren', 'Group')
        }
        catch
        {
        }
    }

    $members = $group.psbase.invoke("members")  | ForEach {
        $_.GetType().InvokeMember("Name",  'GetProperty',  $null,  $_, $null)
    }
    $admins = @()

    if(Get-Module ActiveDirectory)
    {
        foreach($member in $members)
        {  
            try {      
                # Try if $member is a AD group and get all members of this group including all nested groups      
                $admins += (Get-ADGroupMember $member -Recursive | select -ExpandProperty SamAccountName)
            }
            catch
            {
                # TODO catch unterscheiden nach nicht gefunden oder active directory Fehler
                # If it is not a AD group, it has to be a local account, so add it (we assume local groups are not used inside the company)
                $admins += $member
            }
        }
    }
    # Remove duplicated accounts und output the unique ones
    Write-Output $admins | select -Unique
}

function Get-LastInstalledUpdateGroup
{

    $InstalledUpdates = Get-WinEvent -FilterHashtable @{ProviderName='Microsoft-Windows-WindowsUpdateClient';Id=19} | Select-Object -Property *,@{Name='UpdateName';Expression={$_.Properties[0].Value}} | Select-Object TimeCreated, UpdateName
    $date = $InstalledUpdates.TimeCreated | Select-Object -First 1

    $LastInstalledUpdates = @()

    foreach($update in $InstalledUpdates)
    {
        if ($update.TimeCreated.Date -eq $date.Date)
        {
            $LastInstalledUpdates += $update
        }
        else
        {
            break;
        }
    }

    Write-Output $LastInstalledUpdates
}

function Get-LastInstalledSccmUpdateGroup
{
    try
    {
        $AssignedUpdateCIs = Get-CimInstance -Namespace root\ccm\Policy\Machine -ClassName CCM_UpdateCIAssignment -ErrorAction Stop | Select-Object -ExpandProperty AssignedCIs | ForEach-Object { ([XML]$_).CI } | Select-Object -Property @{Name='UpdateId';Expression={$_.ID}},DisplayName 
        $InstalledUpdates = Get-WinEvent -FilterHashtable @{ProviderName='Microsoft-Windows-WindowsUpdateClient';Id=19} | Select-Object -Property *,@{Name='UpdateName';Expression={$_.Properties[0].Value}},@{Name='UpdateId';Expression={$_.Properties[1].Value}}
        
        $UpdatesAssignedAndInstalled = Compare-Object -ReferenceObject $AssignedUpdateCIs -DifferenceObject $InstalledUpdates -Property UpdateId -IncludeEqual | Where-Object { $_.SideIndicator -eq '==' } | Select-Object -ExpandProperty UpdateId
        $InstalledUpdates = $InstalledUpdates | Where-Object { $UpdatesAssignedAndInstalled -contains $_.UpdateId } | Select-Object -Property TimeCreated,UpdateName

        $date = $InstalledUpdates.TimeCreated | Select-Object -First 1

        $LastInstalledUpdates = @()

        foreach($update in $InstalledUpdates)
        {
        if ($update.TimeCreated.Date -eq $date.Date)
        {
            $LastInstalledUpdates += $update
        }
        else
        {
            break;
        }
    }

        Write-Output $LastInstalledUpdates
    }
    catch
    {      
        write-LogFile -Path $LogPath -name $LogName -message "CCM class not found. SCCM client not installed?" -Level Error
        Throw "SCCM client not installed"
    }
}

function Get-FormattedUpdateInformation
{
    $updates = Get-LastInstalledUpdateGroup
    
    if ($updates -eq $null)
    {
        Write-Output "No updates found"
    }
    else
    {
        Write-Output $updates[0].TimeCreated
        Write-Output "<ul>"

        foreach($update in $updates)
        {
            Write-Output "<li>"$update.UpdateName"</li>"
        }
        Write-Output "</ul>"
    }
}

function Get-FormattedSccmUpdateInformation
{
    try
    {
        $updates = Get-LastInstalledSccmUpdateGroup -ErrorAction Stop
    
    
        if ($updates -eq $null)
        {
            Write-Output "No updates found"
        }
        else
        {
            Write-Output $updates[0].TimeCreated"<br/><br/>"
            Write-Output "<ul>"

            foreach($update in $updates)
                    {
            Write-Output "<li>"$update.UpdateName"</li>"
        }
            Write-Output "</ul>"
        }
    }
    catch
    {
        Write-Output "SCCM client not installed"
    }
}

function Get-UpdateHistory 
{
    [CmdletBinding()]
    Param(
        [int]$number = 20
    )

    Get-WinEvent -FilterHashtable @{ProviderName='Microsoft-Windows-WindowsUpdateClient';Id=19} | Select-Object -Property *,@{Name='UpdateName';Expression={$_.Properties[0].Value}} | Select-Object TimeCreated, UpdateName -First $number
}

function Get-SccmDeploymentHistory
{
    [CmdletBinding()]
    Param(
        [int]$number = 20
    )

    try
    {
        Get-CimInstance -Namespace root\ccm\Policy\Machine -ClassName CCM_UpdateCIAssignment -ErrorAction Stop `
        | Select-Object -Property AssignmentName,EnforcementDeadline,StartTime -First $number `
        | Sort-Object -Property EnforcementDeadline -Descending `   
    }
    catch
    {
        # log error 
        write-LogFile -Path $LogPath -name $LogName -message "CCM_UpdateCIAssignment class not found" -Level Error
    }
}

function Test-SystemRestartMayBeNescessary
{
    [Cmdletbinding()]
    Param(
        [int]$withinDays = 7
    )

    # If we have a pending reboot, system definitely has to restart
    if (Get-PendingReboot)
    { Write-Output "yes" }

    # Otherwise check, if there are updates to install within the next $withDays
    else
    {
        try
        {
            $date = (Get-Date).AddDays($withinDays)
        
            Get-CimInstance -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_SoftwareUpdate' -ErrorAction Stop `
            | select -ExpandProperty Deadline `            | ForEach-Object { if ($_.Deadline -le $date) { Write-Output "yes" } else { Write-Output "no" } }

        }
        catch
        {
            Write-Output "SCCM client not installed"
            # log error
            write-LogFile -Path $LogPath -name $LogName -message "CCm class not found. SCCM client not installed?" -Level Error
        }
    }
}

function Get-PendingReboot
{
<#
.Synopsis
    Checks if there is a reboot pending
.DESCRIPTION
    This function looks for a registry branch wiht the ending RebootPending. If it does not exists, then no reboot is necessary.   
.OUTPUTS
    $true if reboot is pending, $false otherwise 
#> 

    $reboot = $false

    try 
    {
        if (Get-item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Stop)
        {
            $reboot = $true
        }
    }
    catch 
    {
        # We do not log anything at this point because in case of an error there is just no reboot pending
    }

    return $reboot
}

function Get-UserLoginHistory
{
<#
.Synopsis
    Gets user login history on machine.
.DESCRIPTION
    Gets user login history on machine within last 7 days by default.  
    
    Logon Types
    ===========
    2  = Logon Typ 2  - Interactive
    3  = Logon Typ 3  - Network
    4  = Logon Typ 4  - Batch
    5  = Logon Typ 5  - Service
    7  = Logon Typ 7  - Unlock
    8  = Logon Typ 8  - NetworkCleartext
    9  = Logon Typ 9  - New Credentials
    10 = Logon Typ 10 - RemoteInteractive
    11 = Logon Typ 11 - CachedInteractive

.PARAMETERS
    $date The date of from which logins are returned    
.OUTPUTS
    
#>

    [CmdletBinding()]
    Param(
        [DateTime]$startDate = (Get-Date).AddDays(-7)
    )

    
    $log = Get-Eventlog -LogName Security -after $startDate

    #$log | where {$_.EventID -eq 4624} | where {($_.ReplacementStrings[8] -eq 2) -or ($_.ReplacementStrings[8] -eq 10)} | select {$_.ReplacementStrings[5], $_.ReplacementStrings[18]}

    #$log | where {$_.EventID -eq 4624} | where {($_.ReplacementStrings[8] -eq 2) -or ($_.ReplacementStrings[8] -eq 10)} | Select-Object -unique  -ExpandProperty ReplacementStrings | select -Index 5,16
    #$log | where {$_.EventID -eq 4624} | where {($_.ReplacementStrings[8] -eq 2) -or ($_.ReplacementStrings[8] -eq 10)}  | foreach {write-ouput $_.TimeGenerated $_.ReplacementStrings[5]} 
    $log | where {$_.EventID -eq 4624} | where {($_.ReplacementStrings[8] -eq 2) -or ($_.ReplacementStrings[8] -eq 10)}  | foreach {
        $obj = New-Object PSObject 
        $obj | Add-Member NoteProperty LogonTime($_.TimeGenerated)
        $obj | Add-Member NoteProperty User($_.ReplacementStrings[5])
        if ($_.ReplacementStrings[8] -eq 2)
        {
            $obj | Add-Member NoteProperty LogonTyp("Interactive")
        }
        else
        {
            $obj | Add-Member NoteProperty LogonTyp("RemoteInteractive")
            $obj | Add-Member NoteProperty IP-Adresse($_.ReplacementStrings[18])
            }
        
       Write-Output $obj
    } | where {$_.User -notlike "DWM-*"}

}

function Get-UserLogins
{
    [CmdletBinding()]
    Param(
        [DateTime]$date = (Get-Date).AddDays(-1)
    )

    Get-WmiObject -class Win32_NetworkLoginProfile |select name, caption, @{Name="lastlogin"; Expression={$_.ConvertToDateTime($_.LastLogon)}} | where lastlogin -GT $date
}

function Get-LocalGroupMember
{
<#
.Synopsis
    Gets all unique members in a local group
.DESCRIPTION
    Gets all unique members in a local group. Recursivley gets members of groups inside the group.     
.PARAMETERS
    $group Name of group 
.OUTPUTS 
    Objects of System.DirectoryServices.AccountManagement.UserPrincipal
#>
    [CmdletBinding()]
    Param (
        # The name of the group 
        [Parameter(Mandatory=$true)]
        $group
    )

    add-type -AssemblyName System.DirectoryServices.AccountManagement
 
    $domain = "$env:computername"
 
    try {
        $domainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain() | select -ExpandProperty Name
        $isDomain = $domainName -match "$domain\."
    }
    catch {
        $isDomain = $false
    }
 
    if ($isDomain) { $ctype = [System.DirectoryServices.AccountManagement.ContextType]::Domain }
    else { $ctype = [System.DirectoryServices.AccountManagement.ContextType]::Machine }
 
    #Create objects to filter based on group name and ContextType--Domain or Machine
    $principal = new-object System.DirectoryServices.AccountManagement.PrincipalContext $ctype,$domain
    $groupPrincipal = new-object System.DirectoryServices.AccountManagement.GroupPrincipal $principal,$group
    $searcher = new-object System.DirectoryServices.AccountManagement.PrincipalSearcher 
    $searcher.QueryFilter = $groupPrincipal
 
    #Note: GetMembers($true) recursively enumerates groups members while GetMembers() simply enumerates group members
    $searcher.FindAll() | foreach {$_.GetMembers($true)} | select -Unique
}

function Get-SPFarmAdministrators 
{
<#
.Synopsis
    Gets all SharePoint Farm administrators.
.DESCRIPTION
    Gets all SharePoint Farm administrators.  
.OUTPUTS 
    All unique members of the SharePoint Farm administrator group by their SamAccountName
#>

    $adminwebapp = Get-SPwebapplication -includecentraladministration | where {$_.IsAdministrationWebApplication}
    $adminsite = Get-SPweb($adminwebapp.Url)
    $AdminGroupName = $adminsite.AssociatedOwnerGroup
    $farmAdministratorsGroup = $adminsite.SiteGroups[$AdminGroupName]
    $users = $adminsite.SiteGroups[$AdminGroupName].users

    foreach ($entry in $users)
    {
        if ($entry.IsDomainGroup)
        {
            $ADUsersInGroup = Get-ADGroupMember -Recursive $entry.Sid | Select -ExpandProperty SamAccountName
            $allAdmins += $ADUsersInGroup   
        }
        else
        {
            $ADUser = Get-ADUser -Identity $entry.sid | Select -ExpandProperty SamAccountName
            $allAdmins += $ADUser
        }
    }

    Write-Output $allAdmins | Select -Unique
}

function Get-SPSiteGroups
{
<#
.Synopsis
    Gets all SharePoint groups to a site.
.DESCRIPTION
    Gets all SharePoint groups to a site.
.PARAMETER
    The URL of the SharePoint site  
.OUTPUTS 
    All SharePoint groups to the given SharePoint site by their name
#>
    [CmdletBinding()]
    Param(
        # the URL of the SharePoint site
        [Parameter(Mandatory=$true)]
        [string]$url
    )

    try
    {
        $site = Get-SPSite $url
        Write-Output $site.OpenWeb().sitegroups | select -ExpandProperty Name
    }
    catch
    {
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error   
    }
}

function Get-SPProductInformation
{

$patchList = @()
$products = Get-SPProduct

if($products.Count -lt 1)
{
    Write-Error "No SharePoint products found."
    break
}

foreach($product in $products.PatchableUnitDisplayNames)
{
    $unit = $products.GetPatchableUnitInfoByDisplayName($product)
    $i = 0

    foreach($patch in $unit.Patches)
    {
        $obj = [PSCustomObject]@{
            DisplayName = ''
            IsLatest = ''
            Patch = ''
            Version = ''
            SupportUrl = ''
            MissingFrom = ''
        }

        $obj.DisplayName = $unit.DisplayName

        if ($unit.LatestPatch.Version.ToString() -eq $unit.Patches[$i].Version.ToString())
        {
            $obj.IsLatest = "Yes"
        }
        else
        {
            $obj.IsLatest = "No"
        }
                        
        if (($unit.Patches[$i].PatchName) -ne [string]::Empty)
        {
            if ($unit.Patches[$i].ServersMissingThis.Count -ge 1)
            {
                $missing = [System.String]::Join(',',$unit.Patches[$i].ServersMissingThis.ServerName)
            }
            else
            {
                $missing = ''
            }

            $obj.Patch = $unit.Patches[$i].PatchName
            $obj.Version = $unit.Patches[$i].Version.ToString()
            $obj.SupportUrl = $unit.Patches[$i].Link.AbsoluteUri
            $obj.MissingFrom = $missing
            $missing = $null
        }
        else
        {
            $obj.Patch = "N/A"
            $obj.Version = "N/A"
            $obj.SupportUrl = "N/A"
            $obj.MissingFrom = "N/A"
        }

        $patchList += $obj
        $obj = $null
        ++$i
    }
}

Write-Output $patchList

}



# Report Functions
# ----------------
<#
    Some functions used for reporting, building reports or convert results to html tables.
#>

function ConvertTo-HtmlTable 
{
<#
.Synopsis
    Converts one or many MBAM Testresult-Objects to a html table 
.DESCRIPTION
    Converts one or many MBAM Testresult-Objects to a html table with one result per row. 
    Newlines are converted into <br> (only in status column!)
#>
    Param(  
        [Parameter(
            Position=0, 
            Mandatory=$true, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)
        ]
        [Alias('Testresult')]
        [PSCustomObject[]]$TestResultObject
    ) 

    Begin 
    {
        Write-Output "<div style=`"overflow-x:auto;`"><table class=`"result-table`"><tr><th>Name</th><th>Task</th><th>Status</th><th>Result</th></tr>"
        $nl = [System.Environment]::NewLine
    }
    
    Process 
    {   
        # Replace system new line with html br
        $status = ($TestResultObject.status).Replace($nl, "<br>")

        if ($TestResultObject.passed -eq "true")
        {
            Write-Output "<tr><td>"$TestResultObject.name"</td><td>"$TestResultObject.task"</td><td>$status</td><td><span class=`"passed`">OK</span></td></tr>"
        }
        elseif ($TestResultObject.passed -eq "false")
        {
            Write-Output "<tr><td>"$TestResultObject.name"</td><td>"$TestResultObject.task"</td><td>$status</td><td><span  class=`"failed`">!</span></td></tr>" 
        }
        elseif ($TestResultObject.passed -eq "warning")
        {
            Write-Output "<tr><td>"$TestResultObject.name"</td><td>"$TestResultObject.task"</td><td>$status</td><td><span  class=`"warning`">!</span></td></tr>" 
        }
    }
    End 
    {
        Write-Output "</table></div>"      
    }
}

function New-SharepointReportSectionHeader
{
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    $resultObjects,
        
    [Parameter(Mandatory=$true)]
    [string]$headertext,

    [string]$anchor
)

    $header = "<h3 id=`"$anchor`" class=`"passed`">$headertext</h3>"
    $errCounter, $warnCounter = 0, 0

    foreach($obj in $resultObjects)
    {
        if ($obj.passed -eq "false") { $errCounter++ }
        if ($obj.passed -eq "warning") { $warnCounter++ }
    } 
    
    if (($errCounter -gt 0) -and ($warnCounter -gt 0))
    { 
        $header = "<h3 id=`"$anchor`">$headertext <div class=`"failed`"> Errors: $errCounter</div> <div class=`"warning`"> Warnings: $warnCounter</div></h3>" 
    }
    elseif (($errCounter -gt 0) -and ($warnCounter -eq 0)) {
        $header = "<h3 id=`"$anchor`">$headertext <div class=`"failed`"> Errors: $errCounter</div></h3>"
    }
    elseif (($warnCounter -gt 0) -and ($errCounter -eq 0))
    {
        $header = "<h3 id=`"$anchor`">$headertext <div class=`"warning`"> Warnings: $warnCounter</div></h3>"
    }
    
    Write-Output $header   
}

function New-SharepointReportNavPoint
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        $resultObjects,
        
        [Parameter(Mandatory=$true)]
        [string]$navPointText,
        
        [Parameter(Mandatory=$true)]
        [string]$anchor 
    )

    $navPoint = "<li><a href=`"#$anchor`">$navPointText <span  class=`"green`">OK</span></a></li>"
    $errCounter, $warnCounter = 0, 0

    foreach($obj in $resultObjects)
    {
        if ($obj.passed -eq "false") { $errCounter++ }
        if ($obj.passed -eq "warning") { $warnCounter++ }
    } 
    
    if (($errCounter -gt 0) -and ($warnCounter -gt 0))
    { 
        $navPoint = "<li><a href=`"#$anchor`">$navPointText <span class=`"red`">$errCounter</span> <span class=`"orange`">$warnCounter</span></a></li>" 
    }
    elseif (($errCounter -gt 0) -and ($warnCounter -eq 0))
    { 
        $navPoint = "<li><a href=`"#$anchor`">$navPointText <span class=`"red`">$errCounter</span></a></li>" 
    }
    elseif (($warnCounter -gt 0) -and ($errCounter -eq 0))
    {
        $navPoint = "<li><a href=`"#$anchor`">$navPointText <span class=`"orange`">$warnCounter</span></a></li>"
    }
    
    Write-Output $navPoint  
}


##############################################################################################
#                                                            
# Section with test case functions for 
# =======================================================================  
# 
# All tests should return an object with following note propertys:
#
#  - Name (String) => the name of test case, i.e. a unique index
#  - Task (String) => which result is expected
#  - Status (String) => short despcription of test result, like "Passed" or a error description
#  - Passed (String) => not passed = false; passed = true; warning = warning
#                                                            
############################################################################################### 


function Test-WebServerRoleState 
{
# TC-SSP-0001
#-------------

<#
.Synopsis
   Checks, if webserver role is installed
.DESCRIPTION
   Checks, if webserver role is installed
.OUTPUTS
    PSCustomObject
#>   

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-SSP-0001")

    $f = Get-WindowsFeature Web-Server 

    $obj | Add-Member NoteProperty Task("Windows Webserver role")
    $obj | Add-Member NoteProperty Status($f.InstallState.ToString())
    if ($f.Installed)
    {
        $obj | Add-Member NoteProperty Passed("true")
    }
    elseif (-not $f.Installed)
    {
        $obj | Add-Member NoteProperty Passed("false")
    }
    else 
    {
        $obj | Add-Member NoteProperty Passed("warning")
    }

    Write-Output $obj
}

function Test-WindowsFeatureState 
{
# TC-SSP-0002
#-------------

<#
.Synopsis
   Checks, if all necessary Windows features for SharePoint are installed
.DESCRIPTION
   Checks, if all necessary Windows features for SharePoint are installed
.PARAMETER
    $featureList A list with all necessary feature. The parameter is set with a default feature list as follows:
            'Net-Framework-Features',
            'Web-Server',
            'Web-WebServer',
            'Web-Common-Http',
            'Web-Static-Content',
            'Web-Default-Doc',
            'Web-Dir-Browsing',
            'Web-Http-Errors',
            'Web-App-Dev',
            'Web-Asp-Net',
            'Web-Net-Ext',
            'Web-ISAPI-Ext',
            'Web-ISAPI-Filter',
            'Web-Health',
            'Web-Http-Logging',
            'Web-Log-Libraries',
            'Web-Request-Monitor',
            'Web-Http-Tracing',
            'Web-Security',
            'Web-Basic-Auth',
            'Web-Windows-Auth',
            'Web-Filtering',
            'Web-Digest-Auth',
            'Web-Performance',
            'Web-Stat-Compression',
            'Web-Dyn-Compression',
            'Web-Mgmt-Tools',
            'Web-Mgmt-Console',
            'Web-Mgmt-Compat',
            'Web-Metabase',
            'Application-Server',
            'AS-Web-Support',
            'AS-TCP-Port-Sharing',
            'AS-WAS-Support', 
            'AS-HTTP-Activation',
            'AS-TCP-Activation',
            'AS-Named-Pipes',
            'AS-Net-Framework',
            'WAS',
            'WAS-Process-Model',
            'WAS-NET-Environment',
            'WAS-Config-APIs',
            'Web-Lgcy-Scripting',
            'Windows-Identity-Foundation',
            'Server-Media-Foundation',
            'Xps-Viewer'
.OUTPUTs
    PSCustomObject
.EXAMPLE
    Test-WindowsFeatureState 
    Name             Task                                                       Status          Passed
    ----             ----                                                       ------          ------
    TC-SSP-0002.1    Windows Feature: .NET Framework 3.5 Features...            Installed       true                                                           
    TC-SSP-0002.2    Windows Feature: Web Server (IIS) (Web-Server)             Installed       true                                                           
    TC-SSP-0002.3    Windows Feature: Web Server (Web-WebServer)                Installed       false
    ...
#>   
    [CmdletBinding()]
    Param(
        $featureList = @(
            'Net-Framework-Features',
            'Web-Server',
            'Web-WebServer',
            'Web-Common-Http',
            'Web-Static-Content',
            'Web-Default-Doc',
            'Web-Dir-Browsing',
            'Web-Http-Errors',
            'Web-App-Dev',
            'Web-Asp-Net',
            'Web-Net-Ext',
            'Web-ISAPI-Ext',
            'Web-ISAPI-Filter',
            'Web-Health',
            'Web-Http-Logging',
            'Web-Log-Libraries',
            'Web-Request-Monitor',
            'Web-Http-Tracing',
            'Web-Security',
            'Web-Basic-Auth',
            'Web-Windows-Auth',
            'Web-Filtering',
            'Web-Digest-Auth',
            'Web-Performance',
            'Web-Stat-Compression',
            'Web-Dyn-Compression',
            'Web-Mgmt-Tools',
            'Web-Mgmt-Console',
            'Web-Mgmt-Compat',
            'Web-Metabase',
            'Application-Server',
            'AS-Web-Support',
            'AS-TCP-Port-Sharing',
            'AS-WAS-Support', 
            'AS-HTTP-Activation',
            'AS-TCP-Activation',
            'AS-Named-Pipes',
            'AS-Net-Framework',
            'WAS',
            'WAS-Process-Model',
            'WAS-NET-Environment',
            'WAS-Config-APIs',
            'Web-Lgcy-Scripting',
            'Windows-Identity-Foundation',
            'Server-Media-Foundation',
            'Xps-Viewer')
    )
    
    $i = 1

    foreach($feature in $featureList)
    {
        $f = Get-WindowsFeature $feature

        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-SSP-0002.$i")
        $name = $f.DisplayName
        $obj | Add-Member NoteProperty Task("Windows Feature: $name ($feature)")
        $obj | Add-Member NoteProperty Status($f.InstallState.ToString())

        if ($f.Installed)
        {
            $obj | Add-Member NoteProperty Passed("true")
        }
        elseif (-not $f.Installed)
        {
            $obj | Add-Member NoteProperty Passed("false")
        }

        Write-Output $obj
        $i++
    }
}

function Test-WebserverServiceState
{
# TC-SSP-0003
#-------------

<#
.Synopsis
   Checks, if the web server services are running
.DESCRIPTION
   Checks, if the web server services are running
.OUTPUTs
   PSCustomObject
#>
    [CmdletBinding()]
    Param(
        $serviceList = @(
            'WAS', 
            'W3SVC')
    )

    $i = 1

    foreach($service in $serviceList)
    {
        $s = Get-service | where name -eq $service

        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-SSP-0003.$i")
        $name = $s.DisplayName
        $obj | Add-Member NoteProperty Task("Webserver service: $name ($service)")

        if($s -ne $null)
        {
            # service found, add status 
            $obj | Add-Member NoteProperty Status(($s.Status).ToString())

            if ($s.Status -eq "running")
            {
                $obj | Add-Member NoteProperty Passed("true")
            }
            else 
            {
                # service paused or stopped
                $obj | Add-Member NoteProperty Passed("warning")
            }
            }
            else 
            {
            # service not found
            $obj | Add-Member NoteProperty Status("Not found")
            $obj | Add-Member NoteProperty Passed("false")

            }

        Write-Output $obj
        $i++
    }
}

function Test-SoftwareInstallState
{
# TC-SSP-0004
#-------------

<#
.Synopsis
    Checks, if all necessary software is installed.
.DESCRIPTION
    Checks, if all necessary software is installed.
.OUTPUTS
    PSCustomObject
#>

    [CmdletBinding()]
    Param(
        $softwareList = @(
            'Microsoft Identity Extensions', 
            'Microsoft SharePoint Foundation 2016 Core',
            'Microsoft SharePoint Server 2016',
            'Microsoft CCR and DSS Runtime 2008 R3',
            'Microsoft Sync Framework Runtime v1.0 SP1 (x64)',
            'Microsoft Visual C++ 2015 x64 Additional Runtime - 14.0.23026',
            'Active Directory Rights Management Services Client 2.1',                                                                                                                                                                                                                    
            'Microsoft SharePoint Foundation 2016 1033 Lang Pack',                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       
            'WCF Data Services 5.6.0 CHT Language Pack',                                                                                                                                                                                                                        
            'WCF Data Services 5.6.0 RUS Language Pack',                                                                                                                                                                                                                        
            'WCF Data Services 5.6.0 KOR Language Pack',                                                                                                                                                                                                                                                                                                                                                                                                                                          
            'WCF Data Services 5.6.0 ESN Language Pack',                                                                                                                                                                                                                                                                                                                                                                                                                      
            'WCF Data Services 5.6.0 FRA Language Pack',                                                                                                                                                                                                                                                                                                                                                                                                                             
            'AppFabric 1.1 for Windows Server',                                                                                                                                                                                                                                 
            'WCF Data Services 5.6.0 Runtime',                                                                                                                                                                                                                                  
            'Microsoft Visual C++ 2012 x64 Additional Runtime - 11.0.61030',                                                                                                                                                                                                                                                                                                                                                                                                                            
            'WCF Data Services 5.6.0 DEU Language Pack',                                                                                                                                                                                                                        
            'Microsoft SQL Server 2012 Native Client ',                                                                                                                                                                                                                                                                                                                                                                                                                                    
            'Microsoft ODBC Driver 11 for SQL Server',                                                                                                                                                                                                                          
            'Microsoft Visual C++ 2012 x64 Minimum Runtime - 11.0.61030',                                                                                                                                                                                                      
            'WCF Data Services 5.6.0 ITA Language Pack',                                                                                                                                                                                                                        
            'WCF Data Services 5.6.0 JPN Language Pack',                                                                                                                                                                                                                        
            'WCF Data Services 5.6.0 CHS Language Pack')
    )

    try 
    {
        $installedSoftList = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select DisplayName | Select -ExpandProperty DisplayName
        $installedSoftList += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select DisplayName | Select -ExpandProperty DisplayName | select -Unique
        $installedSoftList = $installedSoftList | select -Unique
    }
    catch
    {

        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-SSP-0004")
        $obj | Add-Member NoteProperty Task("Software is installed")
        $obj | Add-Member NoteProperty Status("An error occured, see log file for info.")
        $obj | Add-Member NoteProperty Passed("false")
        
        Write-Output $obj
            
        # log error
        $msg = $_.Exception.toString()
        $msg += "; " + $_.ScriptStackTrace.toString()
        write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error

        break
    }
    
    $i = 1

    foreach($software in $softwareList)
    {
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-SSP-0004.$i")
        $obj | Add-Member NoteProperty Task("$software is installed")

        try
        {
            if ($installedSoftList -contains $software)
            {
                $obj | Add-Member NoteProperty Status("Installed")
                $obj | Add-Member NoteProperty Passed("true")
            }
            else
            {
                $obj | Add-Member NoteProperty Status("Not installed")
                $obj | Add-Member NoteProperty Passed("false")
            }
        }
        catch
        {
            $obj | Add-Member NoteProperty Status("An error occured, see log file for info.")
            $obj | Add-Member NoteProperty Passed("false")
            
            # log error
            $msg = $_.Exception.toString()
            $msg += "; " + $_.ScriptStackTrace.toString()
            write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
        }

        Write-Output $obj  
        $i++ 
    } 
}

function Test-SPCentralAdminReachable
{
# TC-SSP-0005
#-------------

<#
.Synopsis
   Checks, if the SharePoint Central Administration site is reachable.
.DESCRIPTION
   Checks, if the SharePoint Central Administration site is reachable.
.OUTPUTS
    PSCustomObject
#>
    
    # Get SharePoint Central Administration URL 
    $url = Get-SPWebApplication -IncludeCentralAdministration | where {$_.IsAdministrationWebApplication} | Select -ExpandProperty Url
     
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-SSP-0005")
    $obj | Add-Member NoteProperty Task("SharePoint Central Administration site $url is reachable")

    try 
    {
        # this web request should fail because it makes a request without credentials, but if we get a 401, the page is running
        Invoke-WebRequest -URI ($url)
    }
    catch [System.Net.WebException]
    {
        # let's check if we are not authorized, which in this case is good because the page seems to be running
        if ($_ -like "*401*Unauthorized*")
        {
            $obj | Add-Member NoteProperty Status("Reachable")
            $obj | Add-Member NoteProperty Passed("true")
        }
        else
        {
            $obj | Add-Member NoteProperty Status("Not reachable")
            $obj | Add-Member NoteProperty Passed("false")
        }
          
    }
    catch
    {
        $obj | Add-Member NoteProperty Status("Not reachable")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message $_.Exception -Level Error
    }

    Write-Output $obj
}

function Test-SPCentralAdminReachableSSL
{
# TC-SSP-0006
#-----------------

<#
.Synopsis
   Checks, if the SharePoint Central Administration site is reachable only over https.
.DESCRIPTION
   Checks, if the SharePoint Central Administration site is reachable only over https.
   A timeout is used for the request because if the site is not running with the tested protocol it could take some time until the request aborts.
   In an intranet environment the request should be resolved fast, therefore the cmdlet works with a timeout of 5 seconds to shorten the operating time.
   If you notice an unexpected behavior, increase the timeout. 
.PARAMETER
    $timeOut Seconds, after the requests timed out. Standard is set to 5.
.OUTPUTS
   PSCustomObject
#>
    [CmdletBinding()]
    Param(
        $timeOut = 5
    )

    # Get SharePoint Central Administration URL 
    $url = Get-SPWebApplication -IncludeCentralAdministration | where {$_.IsAdministrationWebApplication} | Select -ExpandProperty Url

    if ($url.Contains("https"))
    { 
        $urlWithHttps = $url
        $urlWithoutHttps = $url.Replace("https","http")
    }
    else
    {
        $urlWithHttps = $url.Replace("http","https") 
        $urlWithoutHttps = $url
    }

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-SSP-0006")
    $obj | Add-Member NoteProperty Task("The SharePoint Central Administration is only reachable over https") 


    try 
    {
        # this web request should fail because it makes a request without credentials, but if we get a 401, the page is running
        Invoke-WebRequest -URI ($urlWithHttps) -TimeoutSec $timeOut
    }
    catch [System.Net.WebException] 
    { 
        if ($_ -like "*401*Unauthorized*") { $https = $true }
        else { $https = $false }
    }
    catch { $https = $false }
    
    try 
    {
        # this web request should fail because it makes a request without credentials, but if we get a 401, the page is running
        Invoke-WebRequest -URI ($urlWithoutHttps) -TimeoutSec $timeOut
    }
    catch [System.Net.WebException]
    {
       if ($_ -like "*401*Unauthorized*") { $http = $true }
       else { $http = $false }       
    }
    catch { $http = $false }

    if ($https -and (-not $http))
    {
        $obj | Add-Member NoteProperty Status("Only reachable over https")
        $obj | Add-Member NoteProperty Passed("true")
    }
    elseif ($https -and $http)
    {
        $obj | Add-Member NoteProperty Status("Reachable over https and http")
        $obj | Add-Member NoteProperty Passed("warning")
    }
    elseif ((-not $https) -and $http)
    {
        $obj | Add-Member NoteProperty Status("Only reachable over http")
        $obj | Add-Member NoteProperty Passed("warning")
    }
    else
    {
        $obj | Add-Member NoteProperty Status("Not reachable at all")
        $obj | Add-Member NoteProperty Passed("false")
    }
        
    Write-Output $obj
}

function Test-LocalAdmins
{
# TC-SSP-0007
#-------------

<#
.Synopsis
    Tests if the members of the local admin group matches the list of members in the file.
.DESCRIPTION
    Tests if the members of the local admin group matches the list of members in the file.
.INPUTS
    A list of SamAccountNames of members which are assumed to be in the local admin group. Use new-LocalAdminsFile.ps1 in module directory to initally create a snapshot
    of local admin group.
.OUTPUTS
    PSCustomObject  
#>

    Param(
        [Parameter(Mandatory=$true)]
        [Alias('LocalAdminGroupMembers')]
        [string[]] $knownAdmins
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-SSP-0007")
    $obj | Add-Member NoteProperty Task("Members in local admin group are correct")

    $admins = Get-LocalAdmins

    if (-not($admins -eq $null) -and -not($knownAdmins -eq $null))
    {
        $compare = Compare-Object -ReferenceObject $admins -DifferenceObject $knownAdmins

        $nl = [System.Environment]::NewLine

        foreach($member in $compare) 
        {  
            if ($member.SideIndicator -eq "<=")
            {
                $unexpected += $member.InputObject + $nl
                $unexpectedCounter++
            }
            elseif ($member.SideIndicator -eq "=>")
            {
                $missing += $member.InputObject + $nl
                $missingCounter++
            }
        }

        if ($missing -and $unexpected)    
        {
            $obj | Add-Member NoteProperty Status("Not listed members found ($unexpectedCounter): $nl $unexpected $nl Missing members($missingCounter): $nl $missing")
            $obj | Add-Member NoteProperty Passed("false")
            Write-LogFile -Path $LogPath -name $LogName -message "Local admins - not listed members found: $unexpected $nl Missing members: $missing" -Level Error
        }
        elseif ($unexpected) 
        {
            $obj | Add-Member NoteProperty Status("Not listed members found($unexpectedCounter): $nl $unexpected")
            $obj | Add-Member NoteProperty Passed("false") 
            Write-LogFile -Path $LogPath -name $LogName -message "Local admins - not listed members found: $unexpected" -Level Error   
        }
        elseif ($missing)
        {
            $obj | Add-Member NoteProperty Status("Missing members($missingCounter++): $nl $missing")
            $obj | Add-Member NoteProperty Passed("warning")
            Write-LogFile -Path $LogPath -name $LogName -message "Local admins - missing members: $missing" -Level Warning
        }
        else 
        {
            $obj | Add-Member NoteProperty Status("All correct")
            $obj | Add-Member NoteProperty Passed("true")
        }
    }
    else
    {
        $obj | Add-Member NoteProperty Status("An error occured while checking.")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message "An error occured. Either local admins could not be received or file knownLocalAdmins.txt is empty/could not be read"
    }

    Write-Output $obj
}

function Test-LastUserLogins
{
# TC-SSP-0008
#-----------------

<#
.Synopsis
    Checks, if only allowed user have logged in within the last 24 h.
.DESCRIPTION
    Checks, if only allowed user have logged in within the last 24 h. Therefore a list of allowed username is passed to the cmdlet via parameter.
.INPUTS
    $acceptedUsers List of strings with the logon names of the allowed users 
.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    Param(
        [string[]]$acceptedUsers
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-SSP-0008")
    $obj | Add-Member NoteProperty Task("Only expected logins within last 24h on machine")

    $logins = Get-UserLogins

    # Check, if we have any login
    if ($logins -ne $null)
    {
        # Compare logged in usernames with the amount of accepted users to get only the users who are not accepted
        $compare = Compare-Object -ReferenceObject $logins.caption -DifferenceObject $acceptedUsers

        $nl = [System.Environment]::NewLine

        foreach($user in $compare.InputObject)
        {
            foreach($login in $logins)
            {
                if ($user -eq $login.caption)
                {
                    $unexpected += $login.caption + " | " + $login.lastlogin + $nl
                    break
                }
            }
        }
    }

    if ($unexpected) 
    {
        $obj | Add-Member NoteProperty Status("Unexpected logins found: $nl $unexpected")
        $obj | Add-Member NoteProperty Passed("warning") 
        Write-LogFile -Path $LogPath -name $LogName -message "Unexpected logins found: $unexpected" -Level Warning   
    }
    else 
    {
        $obj | Add-Member NoteProperty Status("No unexpected logins found")
        $obj | Add-Member NoteProperty Passed("true")
    }

    Write-Output $obj
}

function Test-DNSServerConnection
{
# TC-SSP-0009
#-----------------

<#
.Synopsis
    Checks, if the DNS servers in the environment are reachable.
.DESCRIPTION
    Checks, if the DNS servers in the environment are reachable. Private network addresses like IPv4 169.* and IPv6 fec0: are skipped.
.OUTPUTS
    PSCustomObject
#>
    $serverIPs = Get-DnsClientServerAddress | select -ExpandProperty ServerAddresses -Unique
    $counter = 1

    foreach($ip in $serverIPs)
    {
        # Check for private network ip addresses and skip them
        if ( (-not $ip.StartsWith("fec0")) -and (-not $ip.StartsWith("169")) )
        {
            $obj = New-Object PSObject
            $obj | Add-Member NoteProperty Name("TC-SSP-0009.$counter")
            $obj | Add-Member NoteProperty Task("DNS-Server with IP $ip is reachable (Ping-Status)")

            if (Test-Connection $ip -ErrorAction SilentlyContinue -Quiet) 
            {
                $obj | Add-Member NoteProperty Status("Reachable")
                $obj | Add-Member NoteProperty Passed("true") 
            }
            else 
            {
                $obj | Add-Member NoteProperty Status("Not reachable")
                $obj | Add-Member NoteProperty Passed("false")
                Write-LogFile -Path $LogPath -name $LogName -message "DNS-server with IP $ip not reachable " -Level Error   
            }

            Write-Output $obj

            $counter++
        }
    }
}

function Test-DefaultDCConnection
{
# TC-SSP-0010
#-----------------

<#
.Synopsis
    Checks, if the default domain controller is reachable with a ping.
.DESCRIPTION
    Checks, if the default domain controller is reachable with a ping.
.OUTPUTS
    PSCustomObject
#>
    
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-SSP-0010")

    try
    {
        $dc = Get-ADDomainController | select -ExpandProperty Name
        $obj | Add-Member NoteProperty Task("Default Domain Controller $dc is reachable (Ping-Status)")

        $connects = Test-Connection (Get-ADDomainController | select -ExpandProperty IPv4Address) -ErrorAction SilentlyContinue

        if ($connects.count -eq 0)
        {
            $obj | Add-Member NoteProperty Status("Not reachable")
            $obj | Add-Member NoteProperty Passed("false") 
            Write-LogFile -Path $LogPath -name $LogName -message "Domain Controller $dc not reachable" -Level Error  
        }

        elseif ($connects.count -le 2)
        {
            $obj | Add-Member NoteProperty Status("Partial reachable (<=50%)")
            $obj | Add-Member NoteProperty Passed("warning")
            Write-LogFile -Path $LogPath -name $LogName -message "Domain Controller $dc partial reachable (<50%)" -Level Warning 
        }

        else
        {
            $obj | Add-Member NoteProperty Status("Reachable")
            $obj | Add-Member NoteProperty Passed("true")           
        }
    }

    catch 
    {
        $obj | Add-Member NoteProperty Task("Default Domain Controller is reachable (Ping-Status)")
        $obj | Add-Member NoteProperty Status("Not reachable")
        $obj | Add-Member NoteProperty Passed("false") 
        Write-LogFile -Path $LogPath -name $LogName -message "Default Domain Controller not reachable" -Level Error  
    }

    Write-Output $obj
}

function Test-ForestDCsConnection
{
# TC-SSP-0011
#-----------------

<#
.Synopsis
   Checks, if the domain controllers in the forest are pingable.
.DESCRIPTION
   Checks, if the domain controllers in the forest are pingable. Default domain controller is skipped, use Test-DefaultDCConnection instead.
.OUTPUTS
   PSCustomObject
#>
Param(
    $exceptionList
)

try
{
    # get default domain controller
    $defaultDC = Get-ADDomainController | select -ExpandProperty IPv4Address
}
catch
{

}
try
{
    # get all domain controller in forest except for default domain controller
    $allDCs = (Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -server $_} | where {$_.IPv4Address -NE $defaultDC}
        
    $i = 1

    # test connection to each dc
    foreach($dc in $allDCs)
    {
        # if $dc is not on the exception list ( with IP or name)
        if ( -not( ($exceptionList.contains($dc.IPv4Address)) -or ($exceptionList.contains($dc.name)) -or ($exceptionList -ne $null) ))
        {
            # test connection, otherwise skip 
            $obj = New-Object PSObject
            $obj | Add-Member NoteProperty Name("TC-SSP-0011.$i")
            $obj | Add-Member NoteProperty Task("Domain Controller "+$dc.Name+"("+$dc.IPv4Address+") is reachable (Ping-Status)")

            if (Test-Connection $dc.IPv4Address -ErrorAction SilentlyContinue -Quiet)
            {
                $obj | Add-Member NoteProperty Status("Reachable")
                $obj | Add-Member NoteProperty Passed("true")
            }

            else
            {
                $obj | Add-Member NoteProperty Status("Not reachable")
                $obj | Add-Member NoteProperty Passed("false") 
                Write-LogFile -Path $LogPath -name $LogName -message "Domain Controller $dc not reachable" -Level Error  
            }

            Write-Output $obj
        }
    }
}
# domain controllers / forest not reachable
catch
{
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-SSP-0011")
    $obj | Add-Member NoteProperty Task("Domain Controller is reachable (Ping-Status)")
    $obj | Add-Member NoteProperty Status("Not reachable")
    $obj | Add-Member NoteProperty Passed("false") 
    Write-Output $obj
        
    Write-LogFile -Path $LogPath -name $LogName -message "Domain Controllers in Forest not reachable" -Level Error  
}
}

function Test-SccmClientUpdates
{
# TC-SSP-0012
#-------------

<#
.Synopsis
    Tests if deployed and applicable updates are installed.
.DESCRIPTION
     Tests if deployed and applicable updates are installed. If updates are available a warning is returned with a list of applicable updates in the status property of the object.
.OUTPUTS
    PSCustomObject  
#>

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-SSP-0012")
    $obj | Add-Member NoteProperty Task("All applicable updates via SCCM are installed.")

    try 
    {
        $SCCMUpdates = Get-CimInstance -Namespace 'root\ccm\ClientSDK' -ClassName 'CCM_SoftwareUpdate' -ErrorAction Stop

        if ($SCCMUpdates -eq $null)
        {
            # No updates applicable
            $obj | Add-Member NoteProperty Status("No updates appliable")
            $obj | Add-Member NoteProperty Passed("true")
        }
        else
        {
            $nl = [System.Environment]::NewLine
            $index = 1

            foreach($update in $SCCMUpdates)
            {
                $status += ($index++).ToString() + ": " + ($update.Name).Substring(0, [System.Math]::Min(75, $update.Name.Length)) + "..."
                $status += $nl + "KB" + $update.ArticleID  + $nl + $nl
                                
            }

            # Updates applicable
            $obj | Add-Member NoteProperty Status("The following updates are applicable" + $nl + $status)
            $obj | Add-Member NoteProperty Passed("warning")

            # Also log applicable updates in logfile
            Write-LogFile -Path $LogPath -name $LogName -message $status -Level Warning
        }
    }
    catch
    {
        $obj | Add-Member NoteProperty Status("SCCM client not installed.")
        $obj | Add-Member NoteProperty Passed("true")
        Write-LogFile -Path $LogPath -name $LogName -message "CCM class not found. SCCM client not installed?" -Level Error
    }    

    Write-Output $obj
}

function Test-LocalGroupMembers
{
# TC-SSP-0013, TC-SSP-0014, TC-SSP-0015
#-------------

<#
.Synopsis
     Tests, if the members in the given group matches the members in the given list
.DESCRIPTION
     Tests, if the members in the given group matches the members in the given list
.OUTPUTS
     PSCustomObject  
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]$group,

        [Parameter(Mandatory=$true)]
        [string[]]$members,

        [string]$id = "TC-SSP-0013"
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name($id)
    $obj | Add-Member NoteProperty Task("Members in local group $group are correct")

    $groupmembers = Get-LocalGroupMember $group | Select -ExpandProperty SamAccountName -Unique

    if (-not($groupmembers -eq $null) -and -not($members -eq $null))
    {
        $compare = Compare-Object -ReferenceObject $groupmembers -DifferenceObject $members

        $nl = [System.Environment]::NewLine

        foreach($member in $compare) 
        {  
            if ($member.SideIndicator -eq "<=")
            {
                $unexpected += $member.InputObject + $nl
                $unexpectedCounter++
            }
            elseif ($member.SideIndicator -eq "=>")
            {
                $missing += $member.InputObject + $nl
                $missingCounter++
            }
        }

        if ($missing -and $unexpected)    
        {
            $obj | Add-Member NoteProperty Status("Not listed members found ($unexpectedCounter): $nl $unexpected $nl Missing members($missingCounter): $nl $missing")
            $obj | Add-Member NoteProperty Passed("false")
            Write-LogFile -Path $LogPath -name $LogName -message "Not listed members found: $unexpected $nl Missing members: $missing" -Level Error
        }
        elseif ($unexpected) 
        {
            $obj | Add-Member NoteProperty Status("Not listed members found($unexpectedCounter): $nl $unexpected")
            $obj | Add-Member NoteProperty Passed("false") 
            Write-LogFile -Path $LogPath -name $LogName -message "Not listed members found: $unexpected" -Level Error   
        }
        elseif ($missing)
        {
            $obj | Add-Member NoteProperty Status("Missing members($missingCounter): $nl $missing")
            $obj | Add-Member NoteProperty Passed("warning")
            Write-LogFile -Path $LogPath -name $LogName -message "Missing members: $missing" -Level Warning
        }
        else 
        {
            $obj | Add-Member NoteProperty Status("All correct")
            $obj | Add-Member NoteProperty Passed("true")
        }
    }
    else
    {
        $obj | Add-Member NoteProperty Status("An error occured while checking.")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message "An error occured. Either local admins could not be received or file knownLocalAdmins.txt is empty/could not be read"
    }

    Write-Output $obj
}

function Test-SPFarmAdministrators
{
# TC-SSP-0016
#-------------

<#
.Synopsis
     Tests, if the members in the SharePoint Farm administrator group are correct.
.DESCRIPTION
     Tests, if the members in the SharePoint Farm administrator group are correct. 
.INPUTS
    An array of strings with all known SharePoint Farm administrator accounts by their SamAccountName.     
    E.G.:
    Administrator
    SharepointDAA
    testuser001
    Peter.Peterson
.OUTPUTS
     PSCustomObject  
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string[]]$admins
    )

    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-SSP-0016")
    $obj | Add-Member NoteProperty Task("Members in SharePoint Farm administrator group are correct")

    $groupmembers = Get-SPFarmAdministrators

    if (-not($groupmembers -eq $null) -and -not($admins -eq $null))
    {
        $compare = Compare-Object -ReferenceObject $groupmembers -DifferenceObject $admins

        $nl = [System.Environment]::NewLine

        foreach($member in $compare) 
        {  
            if ($member.SideIndicator -eq "<=")
            {
                $unexpected += $member.InputObject + $nl
                $unexpectedCounter++
            }
            elseif ($member.SideIndicator -eq "=>")
            {
                $missing += $member.InputObject + $nl
                $missingCounter++
            }
        }

        if ($missing -and $unexpected)    
        {
            $obj | Add-Member NoteProperty Status("Not listed members found ($unexpectedCounter): $nl $unexpected $nl Missing members($missingCounter): $nl $missing")
            $obj | Add-Member NoteProperty Passed("false")
            Write-LogFile -Path $LogPath -name $LogName -message "Not listed members found: $unexpected $nl Missing members: $missing" -Level Error
        }
        elseif ($unexpected) 
        {
            $obj | Add-Member NoteProperty Status("Not listed members found($unexpectedCounter): $nl $unexpected")
            $obj | Add-Member NoteProperty Passed("false") 
            Write-LogFile -Path $LogPath -name $LogName -message "Not listed members found: $unexpected" -Level Error   
        }
        elseif ($missing)
        {
            $obj | Add-Member NoteProperty Status("Missing members($missingCounter): $nl $missing")
            $obj | Add-Member NoteProperty Passed("warning")
            Write-LogFile -Path $LogPath -name $LogName -message "Missing members: $missing" -Level Warning
        }
        else 
        {
            $obj | Add-Member NoteProperty Status("All correct")
            $obj | Add-Member NoteProperty Passed("true")
        }
    }
    else
    {
        $obj | Add-Member NoteProperty Status("An error occured while checking.")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message "An error occured. Either SharePoint Farm admins could not be received or local file with user logins is empty/could not be read"
    }

    Write-Output $obj
}

function Test-SPSiteGroups
{
# TC-SSP-0017
#-------------

<#
.Synopsis
     Tests, if the groups of a SharePoint Farm site are correct.
.DESCRIPTION
     Tests, if the groups of a SharePoint Farm site are correct. 
.INPUTS
    An array of strings with all known SharePoint groups for given site.     
.OUTPUTS
     PSCustomObject  
#>

    try 
    {
        # Get the standard path for target state files
        $path = (Get-Module -ListAvailable SharepointExtensionModule).Path
        $path = $path.Substring(0,$path.LastIndexOf('\'))
        $path += "\data"

        [xml]$xmlReader = Get-Content "$path\allSiteGroups.xml"
    }
    catch
    {
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-SSP-0017")
        $obj | Add-Member NoteProperty Task("Groups SharePoint sites are correct")
        $obj | Add-Member NoteProperty Status("File allSiteGroups.xml with target state not found!")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message "Could not find file allSiteGroups.xml at $path. Please create file with new-SPSiteGroupsFile.ps1 in the modules scripts folder" -Level Error

        # As an error occured, we use return instead of write-output to return to the parent context and leave the function but still get the object
        return $obj 
    }

    # File with target state found and loaded
    # Get all SharePoint sites
    $sites = Get-SPSite | select -ExpandProperty Url

    # Appendix to test case ID
    $i = 1 
    # Newline variable
    $nl = [System.Environment]::NewLine

    # Now check the members of every group for every site
    foreach($site in $sites)
    {

        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-SSP-0017.$i")
        $obj | Add-Member NoteProperty Task("Groups of SharePoint site $site are correct")

        $expectedGroups = $xmlReader.SharePoint.site | where { $_.name -eq $site} | select -ExpandProperty group
        $spGroups = Get-SPSiteGroups $site

        if (-not($spGroups -eq $null) -and -not($expectedGroups -eq $null))
        {
            $compare = Compare-Object -ReferenceObject $spGroups -DifferenceObject $expectedGroups

            # Set counter to zero
            $unexpectedCounter = $missingCounter = 0
            $unexpected = $missing = $null

            foreach($member in $compare) 
            {  
                if ($member.SideIndicator -eq "<=")
                {
                    $unexpected += $member.InputObject + $nl
                    $unexpectedCounter++
                }
                elseif ($member.SideIndicator -eq "=>")
                {
                    $missing += $member.InputObject + $nl
                    $missingCounter++
                }
            }

            if ($missing -and $unexpected)    
            {
                $obj | Add-Member NoteProperty Status("Not listed group(s) found ($unexpectedCounter): $nl $unexpected $nl Missing group(s)($missingCounter): $nl $missing")
                $obj | Add-Member NoteProperty Passed("false")
                Write-LogFile -Path $LogPath -name $LogName -message "Not listed group(s) found: $unexpected $nl Missing group(s): $missing" -Level Error
            }
            elseif ($unexpected) 
            {
                $obj | Add-Member NoteProperty Status("Not listed members found($unexpectedCounter): $nl $unexpected")
                $obj | Add-Member NoteProperty Passed("false") 
                Write-LogFile -Path $LogPath -name $LogName -message "Not listed group(s) found: $unexpected" -Level Error   
            }
            elseif ($missing)
            {
                $obj | Add-Member NoteProperty Status("Missing group(s)($missingCounter): $nl $missing")
                $obj | Add-Member NoteProperty Passed("warning")
                Write-LogFile -Path $LogPath -name $LogName -message "Missing group(s): $missing" -Level Warning
            }
            else 
            {
                $obj | Add-Member NoteProperty Status("All correct")
                $obj | Add-Member NoteProperty Passed("true")
            }
        }
        else
        {
            $obj | Add-Member NoteProperty Status("An error occured while checking.")
            $obj | Add-Member NoteProperty Passed("false")
            Write-LogFile -Path $LogPath -name $LogName -message "An unexpected error occured. "
        }
        $i++
        Write-Output $obj
    }
}

function Test-SPSites
{
# TC-SSP-0019
#-------------

<#
.Synopsis
    Checks, if there are only known SharePoint sites.        
.DESCRIPTION
    Checks, if there are only known SharePoint sites.
.INPUTS
    Reads file spSites.txt in the modules data folder.    
.OUTPUTS
     PSCustomObject  
#>
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-SSP-0019")
    $obj | Add-Member NoteProperty Task("Only known SharePoint sites found")

    try 
    {
        $path = (Get-Module -ListAvailable SharepointExtensionModule).Path
        $path = $path.Substring(0,$path.LastIndexOf('\'))
        $path += "\data"

        # Get SharePoint sites listed in the file
        $siteUrls = Get-Content "$path\spSites.txt" -ErrorAction Stop
    }
    catch 
    {        
        $obj | Add-Member NoteProperty Status("File spSites.txt with target state not found!")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message "Could not find file spSites.txt at $path. Please create file with new-SPSitesFile.ps1 in the modules scripts folder" -Level Error

        # As an error occured, we use return instead of write-output to return to the parent context and leave the function but still get the object
        return $obj 
    }

    # File with sites found, continue
    # Get actual SharePoint sites
    $spSites = Get-SPSite | select -ExpandProperty Url

    if (-not($spSites -eq $null) -and -not($siteUrls -eq $null))
    {
        $compare = Compare-Object -ReferenceObject $spSites -DifferenceObject $siteUrls

        $nl = [System.Environment]::NewLine

        foreach($member in $compare) 
        {  
            if ($member.SideIndicator -eq "<=")
            {
                $unexpected += $member.InputObject + $nl
                $unexpectedCounter++
            }
            elseif ($member.SideIndicator -eq "=>")
            {
                $missing += $member.InputObject + $nl
                $missingCounter++
            }
        }

        if ($missing -and $unexpected)    
        {
            $obj | Add-Member NoteProperty Status("Not listed site found ($unexpectedCounter): $nl $unexpected $nl Missing site ($missingCounter): $nl $missing")
            $obj | Add-Member NoteProperty Passed("false")
            Write-LogFile -Path $LogPath -name $LogName -message "Not listed site found: $unexpected $nl Missing site: $missing" -Level Error
        }
        elseif ($unexpected) 
        {
            $obj | Add-Member NoteProperty Status("Not listed site found($unexpectedCounter): $nl $unexpected")
            $obj | Add-Member NoteProperty Passed("false") 
            Write-LogFile -Path $LogPath -name $LogName -message "Not listed site found: $unexpected" -Level Error   
        }
        elseif ($missing)
        {
            $obj | Add-Member NoteProperty Status("Missing site($missingCounter): $nl $missing")
            $obj | Add-Member NoteProperty Passed("warning")
            Write-LogFile -Path $LogPath -name $LogName -message "Missing site: $missing" -Level Warning
        }
        else 
        {
            $obj | Add-Member NoteProperty Status("All correct")
            $obj | Add-Member NoteProperty Passed("true")
        }
    }
    else
    {
        $obj | Add-Member NoteProperty Status("An error occured while checking.")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message "An error occured."
    }

    Write-Output $obj
}

function Test-SPAllSiteGroupMembers
{
# TC-SSP-0018
#-------------
<#
.Synopsis
    Checks, if all members in a SharePoint group are as expected. This check is done for every group of every SharePoint site.
.DESCRIPTION
    Checks, if all members in a SharePoint group are as expected. This check is done for every group of every SharePoint site.
.INPUTS
    XML file with all SharePoint sites, their groups and their members   
.OUTPUTS
     PSCustomObject  
#>

    try 
    {
        # Get the standard path for target state files
        $path = (Get-Module -ListAvailable SharepointExtensionModule).Path
        $path = $path.Substring(0,$path.LastIndexOf('\'))
        $path += "\data"

        [xml]$xmlReader = Get-Content "$path\allSiteGroupMembers.xml"
    }
    catch
    {
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-SSP-0018")
        $obj | Add-Member NoteProperty Task("Members in groups of SharePoint sites are correct")
        $obj | Add-Member NoteProperty Status("File allSiteGrouMembers.xml with target state not found!")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message "Could not find file allSiteGroupMembers.xml at $path. Please create file with new-SPSiteGroupMembersFile.ps1 in the modules scripts folder" -Level Error

        # As an error occured, we use return instead of write-output to return to the parent context and leave the function but still get the object
        return $obj 
    }

    # File with target state found and loaded
    # Get all SharePoint sites
    $sites = Get-SPSite | select -ExpandProperty Url

    # Appendix to test case ID
    $i = 1 
    # Newline variable
    $nl = [System.Environment]::NewLine

    # Now check the members of every group for every site
    foreach($site in $sites)
    {
        # Get expected groups for current site
        # TODO: site not found in xmlReader
        $expectedGroups = $xmlReader.SharePoint.site | where { $_.name -eq $site} | select -ExpandProperty group

        # Get current groups for current site
        $currentGroups = Get-SPWeb $site | Select -ExpandProperty SiteGroups
            

        # Finally, for each group get members from corresponding file and check them
        foreach($group in $currentGroups)
        {
            # Create the result object
            $obj = New-Object PSObject
            $obj | Add-Member NoteProperty Name("TC-SSP-0018.$i")
            $obj | Add-Member NoteProperty Task("SharePoint site $site $nl -> Members of group '$group' are correct")

            # Clear $currentMembers
            $currentMembers = @()

            # Get the expected members for the current group from target state object, then get the current members of this groupp
            $expectedMembers = $expectedGroups | where { $_.xmlns -eq $group} | select -ExpandProperty UserLogin -ErrorAction SilentlyContinue
            $currentLogins = $group | select -ExpandProperty Users | select -ExpandProperty UserLogin 

            foreach($login in $currentLogins)
            {
                # Check the claim prefix: c:0+.w| means we have a windows security group
                if ($login.contains("c:0+.w|"))
                {
                    # Remove the claim prefix to get the group SID, then get all members of that group
                    $login = $login.Replace("c:0+.w|","")
                    $currentMembers += Get-ADGroupMember $login | select -ExpandProperty samAccountName
                }
                # We have a windows identity claim (Active Directory)
                elseif ($login.contains("i:0#.w|"))
                {
                    $login = $login.Substring($login.LastIndexOf('\')+1)
                    $currentMembers += Get-ADUser $login | select -ExpandProperty samAccountName                 
                }
                # Claim for "Everyone" (authenticated users)
                elseif ($login -eq ("c:0(.s|true"))
                {
                    $currentMembers += "Everyone"
                }
                # Claim for NT AUTHORITY\authenticated users
                elseif ($login -eq ("c:0!.s|windows"))
                {
                    $currentMembers += "NT AUTHORITY\authenticated users"
                }
                else
                {
                    Write-Warning "Found unknown claim prefix: $login" 
                }
            }           

            #  current members and expected members are empty, nothing to compare, everthing is correct
            if ((-not $currentMembers) -and (-not $expectedMembers))
            {
                $obj | Add-Member NoteProperty Status("All correct")
                $obj | Add-Member NoteProperty Passed("true")
            }

            # Found current members and expected members => compare entries 
            elseif ($currentMembers -and $expectedMembers)
            {
                $compare = Compare-Object -ReferenceObject $currentMembers -DifferenceObject $expectedMembers

                # Set counter to zero
                $unexpectedCounter = $missingCounter = 0
                $unexpected = $missing = $null

                # For each member check if it is unexcpected or missing
                foreach($member in $compare) 
                {  
                    if ($member.SideIndicator -eq "<=")
                    {
                        $unexpected += $member.InputObject + $nl
                        $unexpectedCounter++
                    }
                    elseif ($member.SideIndicator -eq "=>")
                    {
                        $missing += $member.InputObject + $nl
                        $missingCounter++
                    }
                }

                if ($missing -and $unexpected)    
                {
                    $obj | Add-Member NoteProperty Status("Not listed member(s) found ($unexpectedCounter): $nl $unexpected $nl Missing member(s) ($missingCounter): $nl $missing")
                    $obj | Add-Member NoteProperty Passed("false")
                    Write-LogFile -Path $LogPath -name $LogName -message "Not listed member(s) found: $unexpected $nl Missing member(s): $missing" -Level Error
                }
                elseif ($unexpected) 
                {
                    $obj | Add-Member NoteProperty Status("Not listed member(s) found($unexpectedCounter): $nl $unexpected")
                    $obj | Add-Member NoteProperty Passed("false") 
                    Write-LogFile -Path $LogPath -name $LogName -message "Not listed member(s) found: $unexpected" -Level Error   
                }
                elseif ($missing)
                {
                    $obj | Add-Member NoteProperty Status("Missing member(s) ($missingCounter): $nl $missing")
                    $obj | Add-Member NoteProperty Passed("warning")
                    Write-LogFile -Path $LogPath -name $LogName -message "Missing member(s): $nl $missing" -Level Warning
                }
                else 
                {
                    $obj | Add-Member NoteProperty Status("All correct")
                    $obj | Add-Member NoteProperty Passed("true")
                }
            }

            # Found current member(s), but no matching expected member(s) => unexcpected member(s)
            elseif ((-not $expectedMembers) -and $currentMembers)
            {
                $obj | Add-Member NoteProperty Status("Unexpected member(s) found: $nl $currentMembers")
                $obj | Add-Member NoteProperty Passed("false")
                Write-LogFile -Path $LogPath -name $LogName -message "Found unexpected member(s) $nl $currentMembers, $nl but no expected members were given" -Level Error
            }

            # No members found but there there are expected members => some member(s) are missing
            elseif ((-not $currentMembers) -and $expectedMembers)
            {
                $obj | Add-Member NoteProperty Status("Missing member(s): $nl $expectedMembers")
                $obj | Add-Member NoteProperty Passed("false")
                Write-LogFile -Path $LogPath -name $LogName -message "Members of group $group of site $site are missing: $nl $expectedMembers"
            }

            # something else happened
            else 
            {
                $obj | Add-Member NoteProperty Status("An error occured")
                $obj | Add-Member NoteProperty Passed("false")
                Write-LogFile -Path $LogPath -name $LogName -message "An undefined error occured."
            }

            Write-Output $obj
            $i++
        }
    }

}

function Test-SPWebAppHttps
{
# TC-SSP-0020
#-------------
<#
.Synopsis
     Checks, that each SharePoint web application URL begins with https
.DESCRIPTION
     Checks, that each SharePoint web application URL begins with https.   
.OUTPUTS
     PSCustomObject  
#>
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty Name("TC-SSP-0020")
    $obj | Add-Member NoteProperty Task("Each SharePoint web application URL begins with https")
    
    # Get all web apps starting with https
    $webApps = Get-SPWebApplication -includeCentralAdministration| where url -like "http://*" | select -ExpandProperty url

    $nl = [System.Environment]::NewLine

    # If true, we found web application not starting with https
    if ($webApps)
    {
        $obj | Add-Member NoteProperty Status("Found web application with http: $nl $webApps")
        $obj | Add-Member NoteProperty Passed("false")
        Write-LogFile -Path $LogPath -name $LogName -message "Found web application not starting with https: $nl $web" -Level Error
    }

    else 
    {
        $obj | Add-Member NoteProperty Status("All correct")
        $obj | Add-Member NoteProperty Passed("true")
    }

    Write-Output $obj
}

function Test-SPBlockedFileTypes
{
# TC-SSP-0022
#-------------
<#
.Synopsis
     Checks, that the list of blocked file types configured in each web application matches the "blacklist" document
.DESCRIPTION
     Checks, that the list of blocked file types configured in each web application matches the "blacklist" document.
     See http://technet.microsoft.com/en-us/library/cc262496.aspx  
     You can pass a list of file types to block, otherwise a default is loaded from the data folder. 
.PARAM
    $blockedFileTypes A list with all blocked file types - the "blacklist" document. If none is given, a default is loaded from the module data folder.
.OUTPUTS
     PSCustomObject  
#>
Param(
    [string[]]$blockedFileTypesTemplate
)

    # Get the standard path for saved files
    $path = (Get-Module -ListAvailable SharepointExtensionModule).Path
    $path = $path.Substring(0,$path.LastIndexOf('\'))
    $path += "\data"    

    try
    {
        $webApps = Get-SPWebApplication -includeCentralAdministration
        if(-not $blockedFileTypesTemplate) { $blockedFileTypesTemplate = Get-Content "$path\blockedFileTypes.txt" }
    }
    catch
    {

    }

    $i = 1

    foreach($webApp in $webApps)
    { 
        $name = $webApp.DisplayName
        $obj = New-Object PSObject
        $obj | Add-Member NoteProperty Name("TC-SSP-0022.$i")
        $obj | Add-Member NoteProperty Task("Blocked file types for $name are correct")

        $blockedFileTypes = $webApp.BlockedFileExtensions
        $result = Compare-Object -ReferenceObject $blockedFileTypes -DifferenceObject $blockedFileTypesTemplate | where SideIndicator -eq "=>"

        if ($result)
        {
            $missingFileTypes = $result | select -ExpandProperty InputObject
            $obj | Add-Member NoteProperty Status("Missing file types in block list, see log file for further info.")
            $obj | Add-Member NoteProperty Passed("false")
            Write-LogFile -Path $LogPath -name $LogName -message "Missing file types in block list $missingFileTypes" -Level Error
        }

        else 
        { 
            $obj | Add-Member NoteProperty Status("All correct")
            $obj | Add-Member NoteProperty Passed("true")
        }

        Write-Output $obj
        $i++
    }

}

# Export functions and variables, access is restricted by manifest file if needed
Export-ModuleMember -Function '*'
Export-ModuleMember -Variable '*':