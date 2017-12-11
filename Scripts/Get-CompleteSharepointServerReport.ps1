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
    Date:             06/03/2017
    Last change:      10/25/2017
    Version:          0.7

#>



<#  
    Configuration
    =================================================================
#>
try 
{
    $Settings = Import-LocalizedData -FileName SharePointReportSettings.psd1 -ErrorAction Stop
}
catch
{
    Write-Error "Report settings file SharePointReportSettings.psd1 not found in this directory!"
    Exit 
}

$year = Get-Date -Format "yyyy"
$month = Get-Date -Format "MM" 

# Set path where reports are saved. If path is empty, set a default path
if ($Settings.Report.reportSavePath -ne "") {$reportSavePath = $Settings.Report.reportSavePath+"$year\$month\"} else { $reportSavePath = "C:\SharePointReports\HTML\$year\$month\" }
if ($Settings.Report.xmlSavePath -ne "") {$xmlSavePath = $Settings.Report.xmlSavePath+"$year\$month\"} else { $xmlSavePath = "C:\SharePointReports\XML\$year\$month\" }


$fileDate = Get-Date -UFormat "%Y%m%d_%H%M"
 

$reportHtmlTitle = "FB Pro GmbH - Sharepoint server report " + (Get-Date -UFormat "%Y%m%d_%H%M") 

$modulePath = (Get-Module -ListAvailable SharepointExtensionModule).Path
$modulePath = $modulePath.Substring(0,$modulePath.LastIndexOf('\'))

$knownAdmins = Get-Content "$modulePath\data\knownLocalAdmins.txt"
$expectedLogins = Get-Content "$modulePath\data\expectedLogins.txt"
$members_WSS_ADMIN_WPG = Get-Content "$modulePath\data\members_WSS_ADMIN_WPG.txt"
$members_WSS_RESTRICTED_WPG_V4 = Get-Content "$modulePath\data\members_WSS_RESTRICTED_WPG_V4.txt"
$members_WSS_WPG = Get-Content "$modulePath\data\members_WSS_WPG.txt"
$spFarmAdmins =  Get-Content "$modulePath\data\knownSPFarmAdmins.txt"
$featureList = @('Net-Framework-Features','Web-Server','Web-WebServer','Web-Common-Http','Web-Static-Content','Web-Default-Doc','Web-Dir-Browsing','Web-Http-Errors','Web-App-Dev','Web-Asp-Net','Web-Net-Ext',
            'Web-ISAPI-Ext','Web-ISAPI-Filter','Web-Health','Web-Http-Logging','Web-Log-Libraries','Web-Request-Monitor','Web-Http-Tracing','Web-Security','Web-Basic-Auth','Web-Windows-Auth','Web-Filtering',
            'Web-Digest-Auth','Web-Performance','Web-Stat-Compression','Web-Dyn-Compression','Web-Mgmt-Tools','Web-Mgmt-Console','Web-Mgmt-Compat','Web-Metabase','Application-Server','AS-Web-Support',
            'AS-TCP-Port-Sharing','AS-WAS-Support','AS-HTTP-Activation','AS-TCP-Activation','AS-Named-Pipes','AS-Net-Framework','WAS','WAS-Process-Model','WAS-NET-Environment','WAS-Config-APIs',
            'Web-Lgcy-Scripting','Windows-Identity-Foundation','Server-Media-Foundation')

<#
    Configuration for short system information in report
    ==============================================
#>
$reportDate = Get-Date -Format g
$currentHost = [System.Net.Dns]::GetHostByName(($env:computerName)) | select -ExpandProperty Hostname
$osInfo = Get-OperatingSystemInfo
$lastBootUpTime = Get-SystemStartupTime
$freeRAM = "{0:N3}" -f ($osInfo.FreePhysicalMemory/1MB)
$freeDiskSpace = "{0:N1}" -f ((get-WmiObject win32_logicaldisk | where DeviceID -eq "C:" | select -ExpandProperty FreeSpace)/1GB)
$logo = $ConfigFile.Settings.Logo
$updates = Get-FormattedUpdateInformation
$sccmUpdates = Get-FormattedSccmUpdateInformation
$restart = Test-SystemRestartMayBeNescessary
If (Get-PendingReboot) { $rebootPending = "yes" } else { $rebootPending = "no" }

<#
    Check and ensure necessary framework conditions
    ===================================================================

    Check conditions like existence of filepath for reports and xml files 
    and create it if necessary.
#>

# Test if path for saving report files exists, otherwise create it
if (!(test-path $reportSavePath))
{
    New-Item -Path $reportSavePath -ItemType Directory -Force
} 

# Test if path for saving XML files exists, otherwise create it
if (!(test-path $xmlSavePath))
{
    New-Item -Path $xmlSavePath -ItemType Directory -Force
}


<# 
    Run testcases and save the results in a variable
    =================================================================== 
#>

Write-Progress -Activity "Generating SharePoint TAP Report" -CurrentOperation "Getting operating system status..." -PercentComplete 10
$spOsStatus = @(
    Test-WebServerRoleState
    Test-WebserverServiceState
    Test-WindowsFeatureState -featureList $featureList
    Test-SccmClientUpdates
)

Write-Progress -Activity "Generating SharePoint TAP Report" -CurrentOperation "Getting SharePoint application status..." -PercentComplete 25
$spApplicationStatus = @(
    Test-SoftwareInstallState
    Test-SPCentralAdminReachable
    Test-SPCentralAdminReachableSSL
)

Write-Progress -Activity "Generating SharePoint TAP Report" -CurrentOperation "Getting securtiy status..." -PercentComplete 55
$spSecurityStatus = @(        
    Test-LocalAdmins -knownAdmins $knownAdmins
    Test-LastUserLogins -acceptedUsers $expectedLogins
    Test-LocalGroupMembers -group "WSS_ADMIN_WPG" -members $members_WSS_ADMIN_WPG
    Test-LocalGroupMembers -group "WSS_RESTRICTED_WPG_V4" -members $members_WSS_RESTRICTED_WPG_V4 -id "TC-SSP-0014"
    Test-LocalGroupMembers -group "WSS_WPG" -members $members_WSS_WPG -id "TC-SSP-0015"
    Test-SPFarmAdministrators -admins $spFarmAdmins
    Test-SPSites
    Test-SPSiteGroups
    Test-SPAllSiteGroupMembers
    Test-SPWebAppHttps
    Test-SPBlockedFileTypes
)

Write-Progress -Activity "Generating SharePoint TAP Report" -CurrentOperation "Getting surrounding environment status..." -PercentComplete 80
$spServerEnvironmentSystemsStatus = @(
    Test-DefaultDCConnection
    Test-DNSServerConnection
    Test-ForestDCsConnection
)

Write-Progress -Activity "Generating SharePoint TAP Report" -CurrentOperation "Building report..." -PercentComplete 90
<#  
    Save results in XML file
    ================================================================================
#>

$allResults = $spServerEnvironmentSystemsStatus + $spOsStatus + $spApplicationStatus + $spSecurityStatus #+ $mbamInfrastructureStatus

# If there are testresult objects, save them in a xml file
if($allResults)
{
    $allResults | Export-Clixml $xmlSavePath"SharepointServer_Report_Objects_$fileDate.xml"
}

$passed, $warning, $failed = 0,0,0

foreach ($result in $allResults)
{
    if($result.passed -eq "true") { $passed++ }
    elseif ($result.passed -eq "warning") { $warning++ }
    elseif ($result.passed -eq "false") { $failed++ }
}

<#  
    Build the report
    ====================================================================
#>
          
$report = "<!DOCTYPE html>
        <html>
            <head>
                <title>$reportHtmlTitle</title>
                <style>
                    html {margin: 0; padding: 0;}
                    body {font-size: 14px; margin: 0; padding: 0 0 10px 0;}
                    h1 {color: #fff;}
                    h1 span {font-size: 1.25em}
                    h3 {margin-top: 40px; padding: 5px; max-width: 40%; text-transform: uppercase;}
                    h1, h2, h3, p, table, img {margin-left: 20px;}
                    ul {list-style-type: square; font-size: 16px;}
                    li {margin-top: 5px; padding: 3px;}
                    li:hover {background-color: #f2f2f2;}
                    li a {text-decoration: none; color: #000}
                    p {font-size: 16px;}
                    table, table.result-table {width: 90%; border: 1px solid darkgrey; border-collapse: collapse;font-family: Arial, sans-serif;}
                    table.info {max-width: 950px; border: 1px solid black; border-collapse: collapse;font-family: Courier, sans-serif;}
                    th {background-color: #d6d6c2; color: white; text-transform: uppercase; font-size: 1.5em; border-bottom: 1px solid darkgray;}
                    th, td {padding: 5px 10px; text-align: left;}
                    tr:nth-child(even) {background-color: #e6e6e6;}
                    tr:hover {background-color: #a6a6a6;}
                    table.result-table td:first-child {width: 15%}
                    table.result-table td:nth-child(2) {width: 50%;}
                    table.result-table td:nth-child(3) {width: 20%;}
                    table.result-table td:last-child {width: 15%;}
                    table.result-table th:last-child {text-align: center;}
                    table.info td:first-child {width: 250px;}
                    table.info td:last-child {width: 700px;}
                    table.info ul {padding-left: 15px;}
                    .header {background-color: #1e90ff; width: 100%; padding: 20px 0;}
                    .header img {text-align: center;}
                    .passed, .green {background-color: #33cc33; color: #fff;}
                    .failed, .red {background-color: #cc0000; color: #fff;}
                    .warning, .orange {background-color: #ff9933; color: #fff;}
                    .green, .red, .orange {width: 25px; height: auto; display: inline-block; text-align: center;}
                    .hostname {color: #3366ff; font-weight: bold;}
                    span.passed, span.failed, span.warning {display: block; padding: 5px; border-radius: 30px; width: 25px; text-align: center; font-weight: bold; margin: auto;}
                </style>
            </head>
            <body>
                <div class=`"header`">
                    <img src=`"$logo`">
                    <h1><span>SharePoint 2016</span> Server Report</h1>
                </div>
                <h2>Server Status-Report</h2>

                <p>Report created at $reportDate on <span class=`"hostname`">$currentHost</span></p>"

# Add overview status to report
$report += "<table><tr><td>Passed: $passed</td><td>Warnings: $warning</td><td>Errors: $failed</td></tr></table>"
# Add a navigation to the report 
$report += "<nav><ul>"
#$report += New-SharepointReportNavPoint -resultObjects $spInfrastructureStatus -navPointText "Infrastructure status" -anchor "1" 
$report += New-SharepointReportNavPoint -resultObjects $spOsStatus -navPointText "Operating System status" -anchor "2" 
$report += New-SharepointReportNavPoint -resultObjects $spApplicationStatus -navPointText "Application status" -anchor "3" 
$report += New-SharepointReportNavPoint -resultObjects $spSecurityStatus -navPointText "Security Status" -anchor "4" 
$report += New-SharepointReportNavPoint -resultObjects $spServerEnvironmentSystemsStatus -navPointText "Server Environment Systems Status" -anchor "5" 
$report += "<li><a href=`"#6`">User Login History</a></li>" 
$report += "<li><a href=`"#7`">Update History</a></li>" 
$report += "<li><a href=`"#8`">SCCM deployment history</a></li>"   
$report += "</ul></nav>"         

# Add a short system overview                
$report +=  "<table class=`"info`">
                <tr>
                    <td>Host:</td>
                    <td>$currentHost</span>
                </tr>
                <tr>
                    <td>Operating System:</td>
                    <td>"+$osInfo.Caption+"</span>
                </tr>
                <tr>
                    <td>OS version:</td>
                    <td>"+$osInfo.Version+"</span>
                        </tr>
                        <tr>
                            <td>Last boot up time:</td>
                            <td>$LastBootUpTime</span>
                        </tr>
                        <tr>
                            <td>OS architecture:</td>
                            <td>"+$osInfo.OSArchitecture+"</span>
                </tr>
                <tr>
                    <td>Free physical memory (GB):</td>
                    <td>$freeRAM</span>
                </tr> 
                <tr>
                    <td>Free disk space (GB):</td>
                    <td>$freeDiskSpace</span>
                </tr>  
                <tr>
                    <td>Last installed updates:</td>
                    <td>$updates</span>
                </tr>   
                <tr>
                    <td>Last installed applicable updates via SCCM:</td>
                    <td>$sccmUpdates</span>
                </tr>  
                <tr>
                    <td>System restart within next 7 days may be nescessary:</td>
                    <td>$restart</td>
                </tr>
                <tr>
                    <td>Reboot pending:</td>
                    <td>$rebootPending</td>
                </tr>                        
            </table>"
 
 try
{      
    
# Get infrastructure status      
#$report += New-SharepointReportSectionHeader -resultObjects $spInfrastructureStatus -headertext "Infrastructure status" -anchor "1"  
#$report += $spInfrastructureStatus | ConvertTo-HtmlTable
        
# Get operating system status      
$report += New-SharepointReportSectionHeader -resultObjects $spOsStatus -headertext "Operating System status" -anchor "2"      
$report += $spOsStatus | ConvertTo-HtmlTable
  
# Get Mbam appliciation status      
$report += New-SharepointReportSectionHeader -resultObjects $spApplicationStatus -headertext "Application status" -anchor "3"      
$report += $spApplicationStatus | ConvertTo-HtmlTable      
        
# Get security status      
$report += New-SharepointReportSectionHeader -resultObjects $spSecurityStatus -headertext "Security Status" -anchor "4"      
$report += $spSecurityStatus | ConvertTo-HtmlTable

# Get and output server environment systems status
$report += New-SharepointReportSectionHeader -resultObjects $spServerEnvironmentSystemsStatus -headertext "Server Environment Systems Status:" -anchor "5"
$report += $spServerEnvironmentSystemsStatus | ConvertTo-HtmlTable         
     
$report += "</table></div>"
# Add user login history to report
$report += Get-UserLoginHistory | ConvertTo-Html -Head "" -PreContent "<h3 id=`"6`">User Login Histroy (last 7 days)</h3>"

# Add update history to report
$report += Get-UpdateHistory -number 20 | ConvertTo-Html -Head "" -PreContent "<h3 id=`"7`">Update History (last 20 installed updates)</h3>"

# Add SCCM deployment history to report
$report += Get-SccmDeploymentHistory -number 20 | ConvertTo-Html -Head "" -PreContent "<h3 id=`"8`">Deployment group history (last 20 assignments)</h3>"

# Closing html tags
$report += "</body></html>"


# Save the report 
$report > $reportSavePath"SharepointServer_report_$fileDate.html"



<#  
    Send error email 
    =================================================================================
#>
#Send-MbamEmailOnError -resultObjects $allResults

}

# Catch any occured error and write it to log file
catch 
{
    $msg = $_.Exception.toString()
    $msg += "; " + $_.ScriptStackTrace.toString()
    write-LogFile -Path $LogPath -name $LogName -message $msg -Level Error
}