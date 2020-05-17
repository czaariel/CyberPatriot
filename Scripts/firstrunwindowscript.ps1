#Run Powershell as admin

#Set execution policy
Set=ExecutionPolicy AllSigned

#Install ProgramManagement
Install-Module ProgramManagement
Import-Module ProgramManagement
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
