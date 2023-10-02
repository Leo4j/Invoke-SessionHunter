# Invoke-SessionHunter
Retrieve and display information about active user sessions on remote computers.

Initially, the tool will check if we have admin access to the target. If we do, we dump sessions informations by accessing the targets via WMI. If we don't, we leverage the remote registry service to query the HKEY_USERS registry hive on the remote computers. We identify and extract Security Identifiers (SIDs) associated with active user sessions, and translate these into corresponding usernames.

It's important to note that the remote registry service needs to be running on the remote computer for the tool to work effectively. In my tests, if the service is stopped but its Startup type is configured to "Automatic" or "Manual", the service will start automatically on the target computer once queried (this is native behavior), and sessions information will be retrieved. If set to "Disabled" no session information can be retrieved from the target.

### Run as follows:

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-SessionHunter/main/Invoke-SessionHunter.ps1')
```

If run without parameters or switches it will retrieve active sessions for all computers in the current domain

```
Invoke-SessionHunter
```

![image](https://github.com/Leo4j/Invoke-SessionHunter/assets/61951374/c0fc2b1e-6edb-42f4-b9a6-d5864115e35f)



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

### Return custom PSObjects instead of table-formatted results

```
Invoke-SessionHunter -RawResults
```

### Show hostnames that returned connection errors

```
Invoke-SessionHunter -ConnectionErrors
```

### Timeout for the initial network scan (default: 50ms)

```
Invoke-SessionHunter -Timeout 100
```

### Do not run a port scan to enumerate for alive hosts before trying to retrieve sessions

Note: if a host is not reachable it will hang for a while

```
Invoke-SessionHunter -NoPortScan
```
