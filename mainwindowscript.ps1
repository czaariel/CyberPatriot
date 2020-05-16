#Main script, to be used after Forensics questions and firstrunscript.ps1 have been run and done
# Turn on AutoUpdates
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 0 /f
net start wuauserv
Set-Content config wuauserv start= auto



#Basic Security
    #Turn on CTL-ALT-DEL logon
    Write-Output "please go enable CTL_ALT_DEL logon at this point"
    Pause
    #Enable firewall
    netsh advfirewall reset
    netsh advfirewall set currentprofile state on
    
    #Disable telnet & FTP
    dism /online /Disable-Feature /FeatureName:TelnetClient
    net stop msftpsvc
    #Turn on UAC
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
    #Turn off RDP
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f


    
#User Management
    #Turn off Guest Account
    net user guest /active no
    #Add a user
    New-Localuser -Name $addmepls -Password $Password -FullName $addmepls -Description "Required in ReadMe"
    ##Remove a user
    Remove-LocalUser -Name $removemepls

# Password Policy
    #Set minimum password length to 8, max password age to 90 days, minimum age to 15 days, and how many passwords are kept to prevent reuse
    net accounts /minpwlen:8 /maxpwage:90 /minpwage:15 /uniquepw:24
    #Turn on audits
    Auditpol /set /Category:System /failure:enable
    auditpol /set /category:* /success:enable
    auditpol /set /category:* /failure:enable
    #Password Lockout Policy (Lockout for 30 minutes after 5 attempts)
    net accounts /lockoutthreshold:5
    net accounts /l
    ockoutduration:30
    ##Enable password expiration
    wmic path Win32_UserAccount where PasswordExpires=false set PasswordExpires=true
    wmic path Win32_UserAccount where Name="Guest" set PasswordExpires=false
    ##Change password?
    Get-ADUser -Filter * -SearchBase "OU=Rotating PW Users,OU=My Users,OU=My Company,DC=MAGICSMILES,DC=local" | Set-ADAccountPassword -Reset -NewPasword (Read-Host -Prompt "Enter Password" -AsSecureString) -WhatIf



#Remove These Files
    #Removes Wireshark
    cuninst Wireshark
    #Removes Angry IP Scanner
    cuninst AngryIPscanner
    #Removes NetBus Pro
    cuninst NetBuspro
