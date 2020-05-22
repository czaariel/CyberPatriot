#Run Powershell as admin

#Set execution policy
Set=ExecutionPolicy Unrestricted
#Fix any potential issues with powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider -Name NuGet


#Install ProgramManagement
Install-Module -Name ProgramManagement
Import-Module -Name ProgramManagement
echo "Use 'Get-Command -Module ProgramManagement' or ' Get-Help <command> -Full'"



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
