#Run Powershell as admin

#Set execution policy
Set=ExecutionPolicy Unrestricted
#Fix any potential issues with powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet
#Install Google Chrome for better browsing
$LocalTempDir = $env:TEMP; $ChromeInstaller = "ChromeInstaller.exe"; (new-object    System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller"); & "$LocalTempDir\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller"; Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name; If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 } else { rm "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose } } Until (!$ProcessesFound)


#Install ProgramManagement
Install-Module -Name ProgramManagement
Import-Module -Name ProgramManagement
echo "Use 'Get-Command -Module ProgramManagement' or ' Get-Help <command> -Full'"



#Set functions for later usage
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
