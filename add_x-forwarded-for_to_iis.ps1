Import-Module webadministration

# find all sites with http or https protocol
$websites = Get-ChildItem IIS:\Sites | ? {  ($_.bindings.Collection.protocol | ? {$_ -eq 'https' -or $_ -eq 'http' } )   }
foreach($site in $websites) {
    $site.Name

    # https://docs.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/site/logfile/customfields/add
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name=`"$($site.name)`"]/logFile/customFields" -name "." -value @{logFieldName='X-Forwarded-For';sourceName='X-Forwarded-For';sourceType='RequestHeader'}

}


#Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name=`"Default Web Site`"]/logFile/customFields" -name '.' | select -ExpandProperty Collection
#Remove-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -filter "system.applicationHost/sites/site[@name=`"Default Web Site`"]/logFile/customFields" -name '.'

