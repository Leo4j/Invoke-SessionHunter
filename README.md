# Invoke-SessionHunter
Retrieve and display information about active user sessions on remote computers. No admin privileges required.

The tool leverages the remote registry service to query the HKEY_USERS registry hive on the remote computer. It identifies and extracts Security Identifiers (SIDs) associated with active user sessions, and translates these into corresponding usernames, offering insights into who is currently logged in to the remote computer.

In pentests and red team exercises, one of the critical objectives is to identify potential points of compromise within the network. Identifying systems with active user sessions becomes invaluable for executing targeted attacks, bolstering the potential for lateral movement, privilege escalation, and domain compromise.

It's important to note that the remote registry service needs to be running on the remote computer for the this tool to work effectively. If the service is stopped but its Startup type is configured to "Automatic" or "Manual", the service will start automatically on the target computer once the tool is run, and sessions information will be retrieved. If set to "Disabled" no session information can be retrieved from the target.

### Run as follows:

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-SessionHunter/main/Invoke-SessionHunter.ps1')
```

If run without parameters or switches it will retrieve active sessions for all computers in the current domain

```
Invoke-SessionHunter
```

![image](https://github.com/Leo4j/Invoke-SessionHunter/assets/61951374/2d75992a-a3bc-4317-9c61-03e192ea0466)


### Specify the target domain

```
Invoke-SessionHunter -Domain contoso.local
```

### Specify a comma-separated list of targets

```
Invoke-SessionHunter -Targets "DC01,Workstation01.contoso.local"
```
	
### Specify the full path to a file containing a list of targets - one per line

```
Invoke-SessionHunter -TargetsFile c:\Users\Public\Documents\targets.txt
```

### Retrieve and display information about active user sessions on servers only

```
Invoke-SessionHunter -Servers
```

### Retrieve and display information about active user sessions on workstations only

```
Invoke-SessionHunter -Workstations
```
	
### Show active session for the specified user only

```
Invoke-SessionHunter -Hunt "Administrator"
```

### Exclude localhost from the sessions retrieval

```
Invoke-SessionHunter -ExcludeLocalHost
```

### Return raw results instead of translating results into a custom PSObject

```
Invoke-SessionHunter -RawResults
```

### Show hostnames that returned connection errors

```
Invoke-SessionHunter -ConnectionErrors
```

### Timeout for the initial network scan

```
Invoke-SessionHunter -Timeout 100
```
