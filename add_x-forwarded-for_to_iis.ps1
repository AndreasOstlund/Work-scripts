<#
.SYNOPSIS
Script to add X-Forwarded-For as a custom log field in IIS
                
.DESCRIPTION
Script to add X-Forwarded-For as a custom log field in IIS

.PARAMETER HeaderName
Specifies the name of the HTTP header.
Default X-FORWARDED-FOR

.PARAMETER LogFieldName
Specifies the fieldname in log file.
Default X-FORWARDED-FOR
Don't use a name with spaces.

.EXAMPLE
add_x-forwarded-for_to_iis.ps1

.EXAMPLE
add_x-forwarded-for_to_iis.ps1 -LogFieldName "ClientAddress"


.NOTES

.LINK
https://github.com/AndreasOstlund/Work-scripts/blob/master/add_x-forwarded-for_to_iis.ps1      

#>
[cmdletBinding()]
Param(
    [Parameter(Mandatory=$False)]
    [string]$HeaderName='X-Forwarded-For'
    ,[Parameter(Mandatory=$False)]
    [string]$LogFieldName='X-Forwarded-For'
)

# set verbose to false for import-module because if verbose is specified for script, import-module will also
# output verbose messages, and that is usually not intended.
Import-Module webadministration -Verbose:$False

# find all sites with http or https protocol
$websites = Get-ChildItem IIS:\Sites | ? {  ($_.bindings.Collection.protocol | ? {$_ -eq 'https' -or $_ -eq 'http' } )   }

foreach($site in $websites) {

    $LogField = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name=`"$($site.name)`"]/logFile/customFields" -name '.' | select -ExpandProperty Collection | ? { $_.logFieldName -eq $LogFieldName -and $_.sourceName -eq $HeaderName }

    if(-not $LogField) {

        Write-Verbose "Adding header $HeaderName as logfield $LogFieldName on site $($site.Name)"
        
        # https://docs.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/site/logfile/customfields/add
        Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  `
            -filter "system.applicationHost/sites/site[@name=`"$($site.name)`"]/logFile/customFields" `
            -name "." `
            -value @{logFieldName="$LogFieldName";sourceName="$HeaderName";sourceType='RequestHeader'}
    } else {
        Write-Warning "A custom log field for header $HeaderName and log field $LogFieldName already exists!"
    }
}


# Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name=`"Default Web Site`"]/logFile/customFields" -name '.' | select -ExpandProperty Collection
# Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name=`"Default Web Site`"]/logFile/customFields" -name '.'


