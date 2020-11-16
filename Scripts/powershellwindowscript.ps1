function runAll {
	clear
	
	#actually runs all functions...
	basicStuff
	registryStuff
	firewallStuff
	userAndPassStuff
	programStuff
	checkAfterStuff
	
}

function basicStuff {
	#Set execution policy
	Set=ExecutionPolicy -ExecutionPolicy Unrestricted
	#Fix any potential issues with powershell
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Install-PackageProvider -Name NuGet

	#Install ProgramManagement
	Install-Module -Name ProgramManagement
	Import-Module -Name ProgramManagement
	echo "Use 'Get-Command -Module ProgramManagement' or ' Get-Help <command> -Full'"
	
	
	$whoyouareloggedinas = (Read-Host "Who are you logged in as?")
	Write-Output $whoyouareloggedinas
	
	# Turn on AutoUpdates
	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 0 /f
	net start wuauserv
	Set-Content config wuauserv start= auto
}


function RemoveThisUser {
        Remove-LocalUser -Name $args
}
    function AddThisUser {
        echo "enter the password you want for the user
        $Password = Read-Host -AsSecureString
        New-LocalUser -name $args -Password $Password -FullName $args -Description "new user"
    }
    function Change2User {
        Remove-LocalGroupMember -Group "Administrators" -Member "$args"
    }
    function Change2Admin {
        Add-LocalGroupMember -Group "Administrators" -Member "$args"
    }



function checkAfterStuff {
	Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize > C:\Users\$whoyouareloggedinas\Documents\InstalledPrograms-PS.txt
}



function userAndPassStuff {

    #Set minimum password length to 8, max password age to 90 days, minimum age to 15 days, and how many passwords are kept to prevent reuse
    net accounts /minpwlen:10 /maxpwage:90 /minpwage:15 /uniquepw:24
    #Turn on audits
    Auditpol /set /Category:System /failure:enable
    auditpol /set /category:* /success:enable
    auditpol /set /category:* /failure:enable
    #Password Lockout Policy (Lockout for 30 minutes after 5 attempts)
    net accounts /lockoutthreshold:5
    net accounts /lockoutduration:30
    ##Enable password expiration
    wmic path Win32_UserAccount where PasswordExpires=false set PasswordExpires=true
    wmic path Win32_UserAccount where Name="Guest" set PasswordExpires=false
    #Turn off Guest Account
	net user guest /active:no
	
	# Set all user passwords to expire
	$Users = (Get-CimInstance -Class win32_useraccount | Where-Object {$_.PasswordExpires -eq $false}).Name
	ForEach($User in $Users) {
	    Get-CimInstance -Query 'Select * from Win32_UserAccount where name LIKE "$User" -Property @{PasswordExpires=$True}
	}
	
	#Change Passwords
	$usersonthiscomp = (Read-Host "List all users on this computer (separated by only comma)").split(",") | %{$_.trim()}

	for ($i=0; $i -lt $usersonthiscomp.length; $i++) {
	    #Clear-Host
	    Write-Output Configuring $usersonthiscomp[$i] properties
	    $deletethisuser = Read-Host Delete $usersonthiscomp[$i]? y or n
	    if ( $deletethisuser -eq "y") {
		Remove-LocalUser -Name $usersonthiscomp[$i]	    	
		Write-Output Use $usersonthiscomp[$i] is deleted
		clear
	    }
	    else {
	    	$adminyn = Read-Host Make $usersonthiscomp[$i] an admin? y or n
		if ( $adminyn -eq "y") {
			Add-LocalGroupMember -Group "Administrators" -Member $usersonthiscomp[$i]
			Write-Output User $usersonthiscomp[$i] is an admin
			clear
			Write-Output To change the password, you must write the name of the current user: $usersonthiscomp[$i]
			$password = ConvertTo-SecureString "CyberPatri0t!" -AsPlainText -Force
			Set-LocalUser -Password $password			
		}
		else {
			Remove-LocalGroupMember -Group "Administrators" -Member $usersonthiscomp[$i]
			Write-Output User $usersonthiscomp[$i] is not an admin
			clear
			Write-Output To change the password, you must write the name of the current user: $usersonthiscomp[$i]
			$password = ConvertTo-SecureString "CyberPatri0t!" -AsPlainText -Force
			Set-LocalUser -Password $password
			Write-Output Password has been changed...
		}
	    }
	    
	}	
}

function firewallStuff {
    #Enable firewall
    netsh advfirewall reset
    netsh advfirewall set currentprofile state on
    #Basic Firewall rules
	netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no 
	netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
	netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no 
	netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no 
	netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no 
	netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no 
	netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
	netsh advfirewall firewall set rule name="netcat" new enable=no
    netsh advfirewall firewall add rule name="Deny Port 22" dir=in action=deny protocol=SSH localport=22
    netsh advfirewall firewall add rule name="Deny Port 80" dir=in action=deny protocol=SMTP localport=25
    netsh advfirewall firewall add rule name="Deny Port 80" dir=in action=deny protocol=POP3 localport=110
    netsh advfirewall firewall add rule name="Deny Port 80" dir=in action=deny protocol=SNMP161 localport=161
    netsh advfirewall firewall add rule name="Deny Port 80" dir=in action=deny protocol=389 localport=389
    #Disable telnet & FTP
    dism /online /Disable-Feature /FeatureName:TelnetClient
    net stop msftpsvc
    #Turn on UAC
    reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
    #Turn off RDP
    	Write-Output "Turning off RDP..."
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
    #Disable LocationTracking
    	Write-Output "Disabling Location Tracking..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
}

#Remove These Files
    #Removes Wireshark
    Uninstall-Program -ProgramName Wireshark -UninstallAllSimilarlyNamedPackages
    #Removes Angry IP Scanner
    Uninstall-Program -ProgramName AngryIPscanner -UninstallAllSimilarlyNamedPackages
    #Removes NetBus Pro
    Uninstall-Program -ProgramName NetBuspro -UninstallAllSimilarlyNamedPackages
    
    
#Basic Registry Information Function ------ Keep at bottom of script for easy navigation without the page being clogged up
function registryStuff {
	#Windows automatic updates
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 4 /f
        reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
        reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
        reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
        reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
	#Restrict CD ROM drive
        reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
	#Do not display last user on logon
	reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
	#Disallow remote access to floppy disks
        reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateFloppies /t REG_DWORD /d 1 /f
	#Disable auto Admin logon
        reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f
	#Clear page file (Will take longer to shutdown)
        reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
	#Prevent users from installing printer drivers 
        reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f
	#Add auditing to Lsass.exe
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
	#Enable LSA protection
        reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_DWORD /d 00000001 /f
	#Limit use of blank passwords
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
	#Auditing access of Global System Objects
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v auditbaseobjects /t REG_DWORD /d 1 /f
	#Auditing Backup and Restore
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v fullprivilegeauditing /t REG_DWORD /d 1 /f
	#Restrict Anonymous Enumeration #1
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymous /t REG_DWORD /d 1 /f
	#Restrict Anonymous Enumeration #2
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
	#Disable storage of domain passwords
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v disabledomaincreds /t REG_DWORD /d 1 /f
	#Take away Anonymous user Everyone permissions
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v everyoneincludesanonymous /t REG_DWORD /d 0 /f
	#Allow Machine ID for NTLM
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v UseMachineId /t REG_DWORD /d 0 /f
	#Do not display last user on logon
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v dontdisplaylastusername /t REG_DWORD /d 1 /f
	#Enable UAC
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
	#UAC setting (Prompt on Secure Desktop)
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
	#Enable Installer Detection
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableInstallerDetection /t REG_DWORD /d 1 /f
	#Disable undocking without logon
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v undockwithoutlogon /t REG_DWORD /d 0 /f
	#Enable CTRL+ALT+DEL
        reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v DisableCAD /t REG_DWORD /d 0 /f
	#Max password age
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v MaximumPasswordAge /t REG_DWORD /d 15 /f
	#Disable machine account password changes
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v DisablePasswordChange /t REG_DWORD /d 1 /f
	#Require strong session key
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireStrongKey /t REG_DWORD /d 1 /f
	#Require Sign/Seal
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v RequireSignOrSeal /t REG_DWORD /d 1 /f
	#Sign Channel
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SignSecureChannel /t REG_DWORD /d 1 /f
	#Seal Channel
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters /v SealSecureChannel /t REG_DWORD /d 1 /f
	#Set idle time to 45 minutes
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v autodisconnect /t REG_DWORD /d 45 /f
	#Require Security Signature - Disabled pursuant to checklist:::
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v enablesecuritysignature /t REG_DWORD /d 0 /f
	#Enable Security Signature - Disabled pursuant to checklist:::
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v requiresecuritysignature /t REG_DWORD /d 0 /f
	#Clear null session pipes
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionPipes /t REG_MULTI_SZ /d "" /f
	#Restict Anonymous user access to named pipes and shares
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /v NullSessionShares /t REG_MULTI_SZ /d "" /f
	#Encrypt SMB Passwords
        reg ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
	#Clear remote registry paths
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths /v Machine /t REG_MULTI_SZ /d "" /f
	#Clear remote registry paths and sub-paths
        reg ADD HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths /v Machine /t REG_MULTI_SZ /d "" /f
	#Enable smart screen for IE8
        reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV8 /t REG_DWORD /d 1 /f
	#Enable smart screen for IE9 and up
        reg ADD "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
	#Disable IE password caching
        reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
	#Warn users if website has a bad certificate
        reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonBadCertRecving /t REG_DWORD /d 1 /f
	#Warn users if website redirects
        reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnOnPostRedirect /t REG_DWORD /d 1 /f
	#Enable Do Not Track
        reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v DoNotTrack /t REG_DWORD /d 1 /f
        reg ADD "HKCU\Software\Microsoft\Internet Explorer\Download" /v RunInvalidSignatures /t REG_DWORD /d 1 /f
        reg ADD "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" /v LOCALMACHINE_CD_UNLOCK /t REG_DWORD /d 1 /f
        reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v WarnonZoneCrossing /t REG_DWORD /d 1 /f
	#Show hidden files
        reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
	#Disable sticky keys
        reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
	#Show super hidden files
        reg ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f
	#Disable dump file creation
	    reg ADD HKLM\SYSTEM\CurrentControlSet\Control\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f
	#Disable autoruns
	    reg ADD HKCU\SYSTEM\CurrentControlSet\Services\CDROM /v AutoRun /t REG_DWORD /d 1 /f
	#Windows Office Security
	reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\12.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\14.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\15.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\15.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Outlook\Security" /v markinternalasunsafe /t REG_DWORD /d 0 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Excel\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security" /v blockcontentexecutionfrominternet /t REG_DWORD /d 1 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Word\Security" /v vbawarnings /t REG_DWORD /d 4 /f
	reg add "HKCU\Software\Policies\Microsoft\Office\16.0\Publisher\Security" /v vbawarnings /t REG_DWORD /d 4 /f	
}

runAll
