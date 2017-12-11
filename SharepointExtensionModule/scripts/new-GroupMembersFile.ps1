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
    Date:             06/26/2017
    Last change:      10/16/2017
    Version:          1.0

#>

<#
.Synopsis
    Creates files for the local SharePoint groups.
.DESCRIPTION
    Creates files for the local SharePoint groups WSS_ADMIN_WPG, WSS_WPG and WSS_RESTRICTED_WPG_V4.
.OUTPUTS
     One .txt with all members for each of the groups.git
#>

try 
{
    # First, get the path of the module and create the data folder (if it does not exist)
    $path = (Get-Module -ListAvailable SharepointExtensionModule).Path
    $path = $path.Substring(0,$path.LastIndexOf('\'))
    $path += "\data"

    if (!(Test-Path -Path $path))
    {
        # Create folder if it not exists
        New-Item -Path $path -ItemType Folder -Force | Out-Null
    }

    Get-LocalGroupMember "WSS_ADMIN_WPG" | Select -ExpandProperty SamAccountName -Unique > "$path\members_WSS_ADMIN_WPG.txt"
    Get-LocalGroupMember "WSS_WPG" | Select -ExpandProperty SamAccountName -Unique > "$path\members_WSS_WPG.txt"
    Get-LocalGroupMember "WSS_RESTRICTED_WPG_V4" | Select -ExpandProperty SamAccountName -Unique > "$path\members_WSS_RESTRICTED_WPG_V4.txt"
}    
catch
{
    Write-Error $_.Exception.Message
}