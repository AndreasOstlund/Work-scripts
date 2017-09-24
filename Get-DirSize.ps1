Function Get-DirectorySize {
<#
	.SYNOPSIS

	.DESCRIPTION
        Requires Powershell 5. Because of -Depth parameter on Get-ChildItem

	.EXAMPLE
        Get-DirectorySize

	.NOTES

	.LINK

#>
#Requires -Version 5
    [cmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$Path
        ,[Parameter(Mandatory=$False)]
        [int]$Depth
    )

    # Generated with New-FortikaPSFunction

	# If -debug is set, change $DebugPreference so that output is a little less annoying.
	#	http://learn-powershell.net/2014/06/01/prevent-write-debug-from-bugging-you/
	If ($PSBoundParameters['Debug']) {
		$DebugPreference = 'Continue'
	}

    if(-not $Depth) {
        $Depth = 0
    }

    
    Get-ChildItem -Path $Path -Depth $Depth -Recurse -Directory | `
        ForEach-Object {
            Write-Debug "$($_.FullName)"

            $Size=$(Get-ChildItem -path $_.FullName  -Recurse -file | Measure-Object -Sum Length)
            if(-not $Size.Sum) {
                $PathSize = 0
            } else {
                $PathSize = $Size.Sum
            }
            New-Object -TypeName PSObject -Property @{ Path = $_.FullName; Size=$PathSize; SizeMB=$([math]::Round($PathSize/(1024*1024),2)) }
        } 


}
