#Run Powershell as admin

#Set execution policy
Set=ExecutionPolicy AllSigned

#Install needed programs
   Install-Module -Name ProgramManagement
   Import-Module ProgramManagement
   Get-Commands -Module ProgramManagement
      #If you need help with commands
   #   Get-Commands -Module ProgramManagement
   #   Get-Help about_ProgramManagement

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
