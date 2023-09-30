function Invoke-SessionHunter {
	
	<#

	.SYNOPSIS
	Invoke-SessionHunter Author: Rob LP (@L3o4j)
	https://github.com/Leo4j/Invoke-SessionHunter

	.DESCRIPTION
	Retrieve and display information about active user sessions on remote computers.
	Admin privileges on the remote systems are not required.
	If run without parameters or switches it will retrieve active sessions for all computers in the current domain.
	The tool leverages the remote registry service to query the HKEY_USERS registry hive on the remote computers.
	It identifies and extracts Security Identifiers (SIDs) associated with active user sessions,
	and translates these into corresponding usernames, offering insights into who is currently logged in.
	It's important to note that the remote registry service needs to be running on the remote computer for the tool to work effectively.
	In my tests, if the service is stopped but its Startup type is configured to "Automatic" or "Manual",
	the service will start automatically on the target computer once queried (this is native behavior),
	and sessions information will be retrieved. If set to "Disabled" no session information can be retrieved from the target.
	
	.PARAMETER Domain
	Specify the target domain
	
	.PARAMETER Targets
	Specify a comma-separated list of targets
	
	.PARAMETER TargetsFile
	Specify the full path to a file containing a list of targets - one per line
	
	.PARAMETER Hunt
	Show active session for the specified user only
	
	.PARAMETER Timeout
	Timeout for the initial network scan (default: 50ms)
	
	.PARAMETER Servers
	Retrieve and display information about active user sessions on servers only
	
	.PARAMETER Workstations
	Retrieve and display information about active user sessions on workstations only
	
	.PARAMETER ExcludeLocalHost
	Exclude localhost from the sessions retrieval
	
	.PARAMETER RawResults
	Return custom PSObjects instead of table-formatted results
	
	.PARAMETER ConnectionErrors
	Show hostnames that returned connection errors

 	.PARAMETER NoPortScan
	Do not run a port scan to enumerate for alive hosts before trying to retrieve sessions

	.EXAMPLE
	Invoke-SessionHunter
	Invoke-SessionHunter -Domain contoso.local
	Invoke-SessionHunter -Domain contoso.local -Servers
	Invoke-SessionHunter -TargetsFile c:\Users\Public\Documents\targets.txt
	Invoke-SessionHunter -Hunt "Administrator"
	
	#>
    
	[CmdletBinding()] Param(
		
		[Parameter (Mandatory=$False, Position = 0, ValueFromPipeline=$true)]
		[String]
		$Domain,
		
		[Parameter (Mandatory=$False, Position = 1, ValueFromPipeline=$true)]
		[String]
		$Targets,
		
		[Parameter (Mandatory=$False, Position = 2, ValueFromPipeline=$true)]
		[String]
		$TargetsFile,
		
		[Parameter (Mandatory=$False, Position = 3, ValueFromPipeline=$true)]
		[String]
		$Hunt,
		
		[Parameter (Mandatory=$False, Position = 4, ValueFromPipeline=$true)]
		[String]
		$Timeout,
		
		[Parameter (Mandatory=$False, Position = 5, ValueFromPipeline=$true)]
		[Switch]
		$Servers,
		
		[Parameter (Mandatory=$False, Position = 6, ValueFromPipeline=$true)]
		[Switch]
		$Workstations,
		
		[Parameter (Mandatory=$False, Position = 7, ValueFromPipeline=$true)]
		[Switch]
		$RawResults,
		
		[Parameter (Mandatory=$False, Position = 8, ValueFromPipeline=$true)]
		[Switch]
		$ConnectionErrors,
		
		[Parameter (Mandatory=$False, Position = 9, ValueFromPipeline=$true)]
		[Switch]
		$ExcludeLocalHost,

  		[Parameter (Mandatory=$False, Position = 10, ValueFromPipeline=$true)]
		[Switch]
		$NoPortScan
	
	)
	
	$ErrorActionPreference = "SilentlyContinue"
	$WarningPreference = "SilentlyContinue"
	Set-Variable MaximumHistoryCount 32767
	
	Add-Type -AssemblyName System.DirectoryServices
	if($Domain){
		$currentDomain = $Domain
	}
	else{
		try{
  			$currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
			$currentDomain = $currentDomain.Name
  		}
    		catch{$currentDomain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-Table -HideTableHeaders | out-string | ForEach-Object { $_.Trim() }}
	}
	$domainDistinguishedName = "DC=" + ($currentDomain -replace "\.", ",DC=")
	$targetdomain = "LDAP://$domainDistinguishedName"
	$searcher = New-Object System.DirectoryServices.DirectorySearcher
	$searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry $targetdomain
 	$searcher.PageSize = 1000
	
	if($TargetsFile){
		$Computers = Get-Content -Path $TargetsFile
		$Computers = $Computers | Sort-Object -Unique
	}
	
	elseif($Targets){
  		$Computers = $Targets
  		$Computers = $Computers -split ","
		$Computers = $Computers | Sort-Object -Unique
	}
	
	elseif($Servers){
		$ldapFilter = "(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
		$searcher.Filter = $ldapFilter
		$allservers = $searcher.FindAll()
		
		$Computers = $null
		$Computers = @()
		foreach ($server in $allservers) {
			$hostname = $server.Properties["dnshostname"][0]
			$Computers += $hostname
		}
		$Computers = $Computers | Sort-Object
	}

	elseif($Workstations){
		$ldapFilter = "(&(objectCategory=computer)(!(operatingSystem=*server*))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
		$searcher.Filter = $ldapFilter
		$allworkstations = $searcher.FindAll()
		
		$Computers = $null
		$Computers = @()
		foreach ($workstation in $allworkstations) {
			$hostname = $workstation.Properties["dnshostname"][0]
			$Computers += $hostname
		}
		$Computers = $Computers | Sort-Object
	}
	
	else{
		$ldapFilter = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
		$searcher.Filter = $ldapFilter
		$allcomputers = $searcher.FindAll()
		
		$Computers = $null
		$Computers = @()
		foreach ($computer in $allcomputers) {
			$hostname = $computer.Properties["dnshostname"][0]
			$Computers += $hostname
		}
		$Computers = $Computers | Sort-Object
	}
	
	if($ExcludeLocalHost){
		$HostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
		$Computers = $Computers | Where-Object {-not ($_ -cmatch "$env:computername")}
		$Computers = $Computers | Where-Object {-not ($_ -match "$env:computername")}
		$Computers = $Computers | Where-Object {$_ -ne "$env:computername"}
		$Computers = $Computers | Where-Object {$_ -ne "$HostFQDN"}
	}

 	if(!$NoPortScan){
	
		$reachable_hosts = $null
		$Tasks = $null
		$total = $Computers.Count
		$count = 0
		
		if(!$Timeout){$Timeout = "50"}
		
		$reachable_hosts = @()
		
		$Tasks = $Computers | % {
			Write-Progress -Activity "Scanning Ports" -Status "$count out of $total hosts scanned" -PercentComplete ($count / $total * 100)
			$tcpClient = New-Object System.Net.Sockets.TcpClient
			$asyncResult = $tcpClient.BeginConnect($_, 135, $null, $null)
			$wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout)
			if($wait) {
   				try{
					$tcpClient.EndConnect($asyncResult)
					$connected = $true
					$reachable_hosts += $_
    				} catch{$connected = $false}
			} else {$connected = $false}
   			$tcpClient.Close()
			$count++
		}
		
		Write-Progress -Activity "Scanning Ports" -Completed
		
		$Computers = $reachable_hosts

 	}
	
	# Create a runspace pool
	$runspacePool = [runspacefactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
	$runspacePool.Open()

	# Create an array to hold the runspaces
	$runspaces = @()

	# Iterate through the computers, creating a runspace for each
	foreach ($Computer in $Computers) {
		# ScriptBlock that contains the processing code
		$scriptBlock = {
			param($Computer, $currentDomain, $ConnectionErrors, $searcher)

			# Clearing variables
			$userSIDs = $null
			$userKeys = $null
			$remoteRegistry = $null
			$user = $null
			$userTranslation = $null
   			$AdminStatus = $False
      			$SessionsAsAdmin = $null
	 		$SessionsAsAdmin = @()
    			$TempHostname = $Computer -replace '\..*', ''

			# Gather computer information
			$ipAddress = Resolve-DnsName $Computer | Where-Object { $_.Type -eq "A" } | Select-Object -ExpandProperty IPAddress

   			# Check Admin Access (and Sessions)
      			$Error.Clear()
	 		$CheckSessionsAsAdmin = wmic /node:$Computer ComputerSystem Get UserName 2>&1
    			if($error[0] -eq $null){
       				$AdminStatus = $True
       				$SessionsAsAdmin += $CheckSessionsAsAdmin | Where-Object {$_ -like "*\*" -AND $_ -notlike "*$TempHostname*"}
	   		}

			# Open the remote base key
			try {
				$remoteRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', $Computer)
			} catch {
				if ($ConnectionErrors) {
					Write-Host ""
					Write-Host "Failed to connect to computer: $Computer"
				}
				continue
			}

			# Get the subkeys under HKEY_USERS
			$userKeys = $remoteRegistry.GetSubKeyNames()

			# Initialize an array to store the user SIDs
			$userSIDs = @()

			foreach ($key in $userKeys) {
				# Skip common keys that are not user SIDs
				if ($key -match '^[Ss]-\d-\d+-(\d+-){1,14}\d+$') {
					$userSIDs += $key
				}
			}

			# Close the remote registry key
			$remoteRegistry.Close()

			$results = @()

			# Resolve the SIDs to usernames
			foreach ($sid in $userSIDs) {
				$user = $null
				$userTranslation = $null

				try {
					$user = New-Object System.Security.Principal.SecurityIdentifier($sid)
					$userTranslation = $user.Translate([System.Security.Principal.NTAccount])

					$results += [PSCustomObject]@{
						Domain           = $currentDomain
						HostName         = $TempHostname
						IPAddress        = $ipAddress
						OperatingSystem  = $null
						Access           = $AdminStatus
						UserSession      = $userTranslation
						AdmCount         = "NO"
					}
				} catch {
					$searcher.Filter = "(objectSid=$sid)"
					$userTranslation = $searcher.FindOne()
					$user = $userTranslation.GetDirectoryEntry()
					$usersam = $user.Properties["samAccountName"].Value
					$netdomain = ([ADSI]"LDAP://$currentDomain").dc -Join " - "
					if ($usersam -notcontains '\') {
						$usersam = "$netdomain\" + $usersam
					}

					$results += [PSCustomObject]@{
						Domain           = $currentDomain
						HostName         = $TempHostname
						IPAddress        = $ipAddress
						OperatingSystem  = $null
						Access           = $AdminStatus
						UserSession      = $usersam
						AdmCount         = "NO"
					}
				}
			}

   			foreach($Session in $SessionsAsAdmin){
      				$results += [PSCustomObject]@{
	  				Domain           = $currentDomain
					HostName         = $TempHostname
					IPAddress        = $ipAddress
					OperatingSystem  = $null
					Access           = $AdminStatus
					UserSession      = $Session
					AdmCount         = "NO"
				}
			}

   			$results = $results | Sort-Object HostName, UserSession | Select-Object -Unique HostName, UserSession, Domain, IPAddress, OperatingSystem, Access, AdmCount

			# Returning the results
			return $results
		}

		$runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($Computer).AddArgument($currentDomain).AddArgument($ConnectionErrors).AddArgument($searcher)
		$runspace.RunspacePool = $runspacePool
		$runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke() }
	}

	# Wait for all runspaces to complete
	$allResults = @()
	foreach ($runspace in $runspaces) {
		$allResults += $runspace.Pipe.EndInvoke($runspace.Status)
		$runspace.Pipe.Dispose()
	}
	
	foreach ($result in $allResults) {
		$username = ($result.UserSession -split '\\')[1]
		$tempdomain = ($result.UserSession -split '\\')[0]
		$TargetHost = $result.HostName
		$result.AdmCount = AdminCount -UserName $username -Searcher $searcher
		$result.OperatingSystem = Get-OS -HostName $TargetHost -Searcher $searcher
	}
	
 	# Show Results

	if($RawResults){
		if($Hunt){
			$allResults | Where-Object { $_.User -like "*$Hunt*" } | Select-Object Domain, HostName, IPAddress, OperatingSystem, Access, UserSession, AdmCount
		}
		else{$allResults | Select-Object Domain, HostName, IPAddress, OperatingSystem, Access, UserSession, AdmCount}
	}
	else{
		if($Hunt){
			$allResults | Where-Object { $_.User -like "*$Hunt*" } | Select-Object Domain, HostName, IPAddress, OperatingSystem, Access, UserSession, AdmCount | Format-Table -AutoSize
		}
		else{$allResults | Select-Object Domain, HostName, IPAddress, OperatingSystem, Access, UserSession, AdmCount | Format-Table -AutoSize}
	}
	
}

function AdminCount {
    param (
        [string]$UserName,
        [System.DirectoryServices.DirectorySearcher]$Searcher
    )

    $Searcher.Filter = "(sAMAccountName=$UserName)"
    $Searcher.PropertiesToLoad.Clear() # Clear any previous properties
    $Searcher.PropertiesToLoad.Add("adminCount") > $null
    
    $user = $Searcher.FindOne()

    if ($user -ne $null) {
        $adminCount = $user.Properties["adminCount"]
        if ($adminCount -eq 1) {
            return $true
        }
    }
    return $false
}

function Get-OS {
    param (
        [string]$HostName,
		[System.DirectoryServices.DirectorySearcher]$Searcher
    )

    $searcher.Filter = "(&(objectCategory=computer)(name=$HostName))"  # Filter to search for a computer with the specified name
	$Searcher.PropertiesToLoad.Clear()
    $searcher.PropertiesToLoad.Add("operatingSystem") > $null # Only load the operatingSystem property

    # Execute the search
    $results = $searcher.FindOne()

    # Check if results were returned and output the operatingSystem property
    if ($results.Count -eq 0) {
        return $null
    } else {
        Write-Output "$($results[0].Properties["operatingsystem"])"
    }
}
