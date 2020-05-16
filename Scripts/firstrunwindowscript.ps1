#Run Powershell as admin

#Set execution policy
Set=ExecutionPolicy AllSigned

#Install chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

#Set functions for later usage
   function RemoveThisUser {
        Remove-LocalUser -Name $args
    }
    function AddThisUser {
        New-LocalUser -name $args -Password $Password -FullName $args -Description "new user"
    }
    function Change2User {
        Remove-LocalGroupMember -Group "Administrators" -Member "$args"
    }
    function Change2Admin {
        Add-LocalGroupMember -Group "Administrators" -Member "$args"
    }
