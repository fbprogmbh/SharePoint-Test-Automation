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
    Date:             07/17/2017
    Last change:      10/16/2017
    Version:          1.0

#>

<#
.Synopsis
    Creates a xml file with all sites and their groups. 
.DESCRIPTION
    Creates a xml file in the SharePointExtentionModule data directory. The file contains nodes for each SharePoint site and their groups.     
.OUTPUTS
    A xml file.
#>

if (Get-PSSnapin -registered Microsoft.SharePoint.PowerShell)
{
    Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction SilentlyContinue

    try 
    {
        $path = (Get-Module -ListAvailable SharepointExtensionModule).Path
        $path = $path.Substring(0,$path.LastIndexOf('\'))
        $path += "\data"

        if (!(Test-Path -Path $path))
        {
            # Create folder if it not exists
            New-Item -Path $path -ItemType Folder -Force | Out-Null
        }

        # Get current date
        $date = Get-Date –f "yyyy-MM-dd HH:mm:ss"

        # Create a new XML object pointing to the file in the data directory 
        $xmlWriter = New-Object System.xml.XmlTextWriter("$path\allSiteGroups.xml",$null)

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
            
            $groups = Get-SPSiteGroups $site.Url

            foreach($group in $groups)
            {
                $xmlWriter.WriteElementString("group", "$group")
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