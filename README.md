# SharePoint Test Automation Package v1

## Overview ##
The SharePoint Test Automation Package gives you the ability to get an overview about the availability and security status of your SharePoint Single-Server. 


## Getting started ##

### Requirements ###
* Some scripts need the PowerShell Active Directory Cmdlets. Add the RSAT AD Tools with the Server Manager or run the PowerShell Cmdlet 

```powershell 
add-windowsfeature RSAT-AD-PowerShell
```

* Download or clone the package
* Adjust your execution policy to at least remoteSigned (the scripts are not digitally signed yet)

```powershell
Set-ExecutionPolicy RemoteSigned -scope CurrentUser
```

* Copy/put the following folders in a PowerShell default load path to get the modules and automatically loaded.  

  * SharePointExtensionModule

	A default load path could be e.g. the path in your user profile under *"userprofile"\Documents\WindowsPowerShell\Modules* (if it does not exists, you have to create it) or the new location under  *C:\Program Files\WindowsPowerShell\Modules*.
For a easy start you can use the **Install-SharepointExtensionModule.ps1** script to add the current path of your cloned/unzipped package location into the PowerShell module path environment variable.

* To run the report script you have to create some files with expected users, SharePoint sites etc. Run the following PowerShell Scripts inside the *SharepointExtensionModule\scripts* folder
  
  * new-GroupMembersFile.ps1
  * new-LocalAdminsFile.ps1
  * new-SPFarmAdminsFile.ps1
  * new-SPSiteGroupMembersFile.ps1
  * new-SPSiteGroupsFile.ps1
  * new-SPSitesFile.ps1
  
Furthermore create a file *expectedLogins.txt* which lists all users (must contain the SAMAccountName, one per line) who are allowed to login at the machine.

### Settings ###
In order to use some functions for the  report you can adjust some settings in the file *Settings.psd1* which is located inside the SharePointExtensionModule folder. This file contains settings used by the SharepointExtensionModule.

* For example, to use the email reporting function first add your email settings

```powershell
Email = @{
            SMTPServer = "smtp.example.com"
            SMTPPort = 25
            MailTo = "sp@example.com"
            MailFrom = "Sharepoint Error Reporting"
            Encoding = "UTF8"
            User = "user@example.com"
            PasswordFile = ""
        }
```

* Its possibile to add a logo to your report. You can change the Base64 string for the variable *logo* or exchange it to an URI. We recommend to use a Base64 string.


Another settings file named *SharePointReportSettings.psd1* contains some settings for the report itself. For example, in the report section the location for the html and xml files can be set. Furthermore you can adjust the report title within the same section.

```powershell
Report = @{
        reportHtmlTitle = "FB Pro GmbH - Sharepoint server report " 
        reportSavePath = "C:\inetpub\wwwroot\reports\Reports\"
        xmlSavePath = "C:\inetpub\wwwroot\reports\XML\"
    }
```



## Usage ##

### HTML reports ###
After all settings meet your enviroment, you simple can create a html report by running the script *Get-CompleteSharepointServerReport.ps1* in an elevated PowerShell console.
Please note that the user running the script must have full read rights on every Sharepoint web application. SEe section troubleshooting for further infos.


## Sample report ##
You can find a sample report in the [Sample](Sample) folder.

## Troubleshooting ##

* Tested on a SharePoint 2016 Single-Server instance. To test a Multi-Server farm you have to run the script on each Web-Frontend Server  to get a consolidate compliance status.

* The user running the script must have at least read permissions for all web applications otherwise the test for site collection group members will not work. To grant read permissions, go to **SharePoint Central Administration**, click *Manage Web Application* under Application Management and select a web application. In the ribbon menue bar select *User Policy* and add the user to **All Zones** with **Full Read** permissions. Repeat for every other web application except for the *SharePoint Central Administration v4* web application.

