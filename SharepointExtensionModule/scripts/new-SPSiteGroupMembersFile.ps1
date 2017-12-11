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
    Date:             07/20/2017
    Last change:      10/16/2017
    Version:          1.0

#>

<#
.Synopsis
    Creates a xml file with all sites, their groups and their members.
.DESCRIPTION
    Creates a xml file in the SharePointExtentionModule data directory. The file contains nodes for each SharePoint site, their groups and their members.
.OUTPUTS
    A xml file. 
#>


if (Get-PSSnapin -registered Microsoft.SharePoint.PowerShell)
{
    Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue

    try 
    {
        # First, get the path of the module and create the data folder (if it does not exist)
        $path = (Get-Module -ListAvailable SharepointExtensionModule).Path
        $path = $path.Substring(0,$path.LastIndexOf('\'))
        $path += "\data"

        if (!(Test-Path -Path $path))
        {
            # Create folder
            New-Item -Path $path -ItemType Folder -Force | Out-Null
        }

        # Get current date
        $date = Get-Date –f "yyyy-MM-dd HH:mm:ss"

        # Create a new XML object pointing to the file in the data directory 
        $xmlWriter = New-Object System.xml.XmlTextWriter("$path\allSiteGroupMembers.xml",$null)

        # Some settings for formatting
        $xmlWriter.Formatting = "Indented"
        $xmlWriter.Indentation = 1
        $xmlWriter.IndentChar = "`t"

        # Start the xml document
        $xmlWriter.WriteStartDocument()

        # Write root node with attributes
        $xmlWriter.WriteStartElement("SharePoint")
        $xmlWriter.WriteAttributeString("timeCreated", "$date") 
        $xmlWriter.WriteAttributeString("host", "$env:computername")


        # Get all SharePoint sites
        $sites = Get-SPSite        
        
        # For each site create a site node and add group nodes for every group of this site
        foreach($site in $sites)
        {
            $xmlWriter.WriteStartElement("site")
            $xmlWriter.WriteAttributeString("name", $site.Url)
            
            $groups = Get-SPWeb $site.Url | Select -ExpandProperty SiteGroups

            foreach($group in $groups)
            {
                $xmlWriter.WriteStartElement("group", $group.Name)

                $logins = $group | select -ExpandProperty Users | select -ExpandProperty UserLogin

                foreach($login in $logins)
                {
                    # Check the claim prefix: c:0+.w| means we have a windows security group
                    if ($login.contains("c:0+.w|"))
                    {
                        # Remove the claim prefix to get the group SID, then get all members of that group
                        $login = $login.Replace("c:0+.w|","")
                        $samAccountNames = Get-ADGroupMember $login | select -ExpandProperty samAccountName

                        foreach($samAccountName in $samAccountNames)
                        {
                            $xmlWriter.WriteElementString("UserLogin", $samAccountName)
                        }
                    }
                    # Claim is a user windows identity claim (Active Directory)
                    elseif ($login.contains("i:0#.w|"))
                    {
                        $login = $login.Substring($login.LastIndexOf('\')+1)
                        $samAccountName = Get-ADUser $login | select -ExpandProperty samAccountName
                        $xmlWriter.WriteElementString("UserLogin", $samAccountName)
                    }
                    # Claim for "Everyone" (authenticated users)
                    elseif ($login -eq ("c:0(.s|true"))
                    {
                        $xmlWriter.WriteElementString("UserLogin", "Everyone")
                    }
                    # Claim for NT AUTHORITY\authenticated users
                    elseif ($login -eq ("c:0!.s|windows"))
                    {
                        $xmlWriter.WriteElementString("UserLogin", "NT AUTHORITY\authenticated users")
                    }
                    else
                    {
                        Write-Warning "Found unknown claim prefix: $login" 
                    }
                }
                $xmlWriter.WriteEndElement()

            }
            $xmlWriter.WriteEndElement()
        }

        # Close root node and document, flush and close stream
        $xmlWriter.WriteEndElement()
        
        $xmlWriter.WriteEndDocument()
        $xmlWriter.Flush()
        $xmlWriter.Close()

    } 
       
    catch
    {
        Write-Error $_.Exception.Message
    }
}
else
{
    Write-Warning "PSSnapin Microsoft.SharePoint.PowerShell not found!" 
}