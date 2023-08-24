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
	
	if($TargetsFile){
		$Computers = Get-Content -Path $TargetsFile
		$Computers = $Computers | ForEach-Object { $_ -replace '\..*', '' }
		$Computers = $Computers | Sort-Object -Unique
		
		$computerDetails = @{}
		
		foreach ($computer in $Computers) {
			$ldapFilter = "(&(objectCategory=computer)(cn=$computer))"
			$searcher.Filter = $ldapFilter
			$result = $searcher.FindOne()
			$name = $computer
			$OS = $result.Properties["operatingsystem"][0]
			$computerDetails[$name] = $OS
		}
	}
	
	elseif($Targets){
  		$Computers = $Targets
  		$Computers = $Computers -split ","
		$Computers = $Computers | ForEach-Object { $_ -replace '\..*', '' }
		$Computers = $Computers | Sort-Object -Unique
		
		$computerDetails = @{}
		
		foreach ($computer in $Computers) {
			$ldapFilter = "(&(objectCategory=computer)(cn=$computer))"
			$searcher.Filter = $ldapFilter
			$result = $searcher.FindOne()
			$name = $computer
			$OS = $result.Properties["operatingsystem"][0]
			$computerDetails[$name] = $OS
		}
	}
	
	elseif($Servers){
		$ldapFilter = "(&(objectCategory=computer)(operatingSystem=*server*))"
		$searcher.Filter = $ldapFilter
		$allservers = $searcher.FindAll()
		
		$computerDetails = @{}
		foreach ($server in $allservers) {
			$name = $server.Properties["name"][0]
			$OS = $server.Properties["operatingsystem"][0]
			$computerDetails[$name] = $OS
		}
		
		$Computers = $null
		$Computers = @()
		foreach ($server in $allservers) {
			$hostname = $server.Properties["name"][0]
			$Computers += $hostname
		}
		$Computers = $Computers | Sort-Object
	}

	elseif($Workstations){
		$ldapFilter = "(&(objectCategory=computer)(!(operatingSystem=*server*)))"
		$searcher.Filter = $ldapFilter
		$allworkstations = $searcher.FindAll()
		
		$computerDetails = @{}
		foreach ($workstation in $allworkstations) {
			$name = $workstation.Properties["name"][0]
			$OS = $workstation.Properties["operatingsystem"][0]
			$computerDetails[$name] = $OS
		}
		
		$Computers = $null
		$Computers = @()
		foreach ($workstation in $allworkstations) {
			$hostname = $workstation.Properties["name"][0]
			$Computers += $hostname
		}
		$Computers = $Computers | Sort-Object
	}
	
	else{
		$ldapFilter = "(objectCategory=computer)"
		$searcher.Filter = $ldapFilter
		$allcomputers = $searcher.FindAll()
		
		$computerDetails = @{}
		foreach ($computer in $allcomputers) {
			$name = $computer.Properties["name"][0]
			$OS = $computer.Properties["operatingsystem"][0]
			$computerDetails[$name] = $OS
		}
		
		$Computers = $null
		$Computers = @()
		foreach ($computer in $allcomputers) {
			$hostname = $computer.Properties["name"][0]
			$Computers += $hostname
		}
		$Computers = $Computers | Sort-Object
	}
	
	if($Domain){
		$ComputersFQDN = $Computers | ForEach-Object {
			if (-Not $_.EndsWith($Domain)) {
				"$_.$Domain"
			} else {
				$_
			}
		}
		$Computers = $ComputersFQDN
	}
	else{
		$ComputersFQDN = $Computers | ForEach-Object {
			if (-Not $_.EndsWith($currentDomain)) {
				"$_.$currentDomain"
			} else {
				$_
			}
		}
		$Computers = $ComputersFQDN
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
				$tcpClient.EndConnect($asyncResult)
				$tcpClient.Close()
				$reachable_hosts += $_
			} else {}
			$count++
		}
		
		Write-Progress -Activity "Scanning Ports" -Completed
		
		$Computers = $reachable_hosts

 	}
	
	if(!$Domain){
		$Computers = $Computers | ForEach-Object { $_ -replace '\..*', '' }
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
			param($Computer, $currentDomain, $ConnectionErrors, $computerDetails, $searcher)

			# Clearing variables
			$userSIDs = $null
			$userKeys = $null
			$remoteRegistry = $null
			$user = $null
			$userTranslation = $null

			$results = @()

			# Gather computer information
			$ipAddress = Resolve-DnsName $Computer | Where-Object { $_.Type -eq "A" } | Select-Object -ExpandProperty IPAddress
			$operatingSystem = $computerDetails[$Computer.Replace(".$currentDomain", "")]

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
						HostName         = $Computer.Replace(".$currentDomain", "")
						IPAddress        = $ipAddress
						OperatingSystem  = $operatingSystem
						UserSession      = $userTranslation
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
						HostName         = $Computer.Replace(".$currentDomain", "")
						IPAddress        = $ipAddress
						OperatingSystem  = $operatingSystem
						UserSession      = $usersam
					}
				}
			}

			# Returning the results
			return $results
		}

		$runspace = [powershell]::Create().AddScript($scriptBlock).AddArgument($Computer).AddArgument($currentDomain).AddArgument($ConnectionErrors).AddArgument($computerDetails).AddArgument($searcher)
		$runspace.RunspacePool = $runspacePool
		$runspaces += [PSCustomObject]@{ Pipe = $runspace; Status = $runspace.BeginInvoke() }
	}

	# Wait for all runspaces to complete
	$allResults = @()
	foreach ($runspace in $runspaces) {
		$allResults += $runspace.Pipe.EndInvoke($runspace.Status)
		$runspace.Pipe.Dispose()
	}

 	# Show Results
	if($RawResults){
		if($Hunt){
			$allResults | Where-Object { $_.User -like "*$Hunt*" } | Select-Object Domain, HostName, IPAddress, OperatingSystem, UserSession
		}
		else{$allResults | Select-Object Domain, HostName, IPAddress, OperatingSystem, UserSession}
	}
	else{
		if($Hunt){
			$allResults | Where-Object { $_.User -like "*$Hunt*" } | Select-Object Domain, HostName, IPAddress, OperatingSystem, UserSession | Format-Table -AutoSize
		}
		else{$allResults | Select-Object Domain, HostName, IPAddress, OperatingSystem, UserSession | Format-Table -AutoSize}
	}
}
