﻿<#
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
    FB Pro Gmbh | Install-SharePointExtensionModule.ps1
    Author(s):        Dennis Esly
    Date:             06/10/2017
    Last change:      06/10/2017
    Version:          1.0

    Adds the folder with the Sharepoint Extension Module to the PowerShell module path.
#>


$currentEnvPath = [Environment]::GetEnvironmentVariable("PSModulePath", "Machine")
$additionalEnvPath = $PSScriptRoot

if (-not($currentEnvPath -like "*$additionalEnvPath*"))
{
    [Environment]::SetEnvironmentVariable("PSModulePath", $currentEnvPath + ";$additionalEnvPath", "Machine")
    Write-Host "Path of SharePoint Extension module added to PSModulePath." -ForegroundColor Green
}
else
{
    Write-Host "Path of SharePoint Extension module already added to PSModulePath." -ForegroundColor Green
}
