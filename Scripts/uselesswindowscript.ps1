

Param()
 
$prompt = "Enter the user's SAMAccountname"
$Title = "Reset Password"
$Default = $null
 
Add-Type -AssemblyName "microsoft.visualbasic" -ErrorAction Stop
#use a VBScript style input box to prompt for the user name
$username = [microsoft.visualbasic.interaction]::InputBox($Prompt,$Title,$Default)
 
if ($username) {
    #prompt for the new password
    $prompt = "Enter the user's new password"
    $Plaintext =[microsoft.visualbasic.interaction]::InputBox($Prompt,$Title,$Default)
 
    #convert to secure string
    $NewPassword = ConvertTo-SecureString -String $Plaintext -AsPlainText -Force
 
    #define a hash table of parameter values to splat to 
    #Set-ADAccountPassword
    $paramHash = @{
    Identity = $Username
    NewPassword = $NewPassword 
    Reset = $True
    Passthru = $True
    ErrorAction = "Stop"
    }
 
    Try {
     $output = Set-ADAccountPassword @paramHash |
     Set-ADUser -ChangePasswordAtLogon $True -PassThru |
     Get-ADuser -Properties PasswordLastSet,PasswordExpired,WhenChanged | Out-String
 
     #display user in a message box
     $message = $output
     $button = "OKOnly"
     $icon = "Information"
     [microsoft.visualbasic.interaction]::Msgbox($message,"$button,$icon",$title) | Out-Null
    }
    Catch {
        #display error in a message box
        $message =  "Failed to reset password for $Username. $($_.Exception.Message)"
        $button = "OKOnly"
        $icon = "Exclamation"
       [microsoft.visualbasic.interaction]::Msgbox($message,"$button,$icon",$title) | Out-Null
    }
} #if user specified
