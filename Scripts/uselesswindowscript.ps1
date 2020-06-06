Write-Output "Hello"
$loggedinas = Read-Host "Who are you logged in as? ex bwayne"

function cont {
    
	$contyn = Read-Host "Continue? answer with y or n"
	if ( $contyn -eq "n") {
		Write-Output "Exitng"
		exit
	}
	
}

function runAll {

	updates
	firewall
	regconfig
	userconfig
	passwordpol
	audits
	removeprograms

}


function updates {

	Write-Output "Configuring updates..."
	Install-Module PSWindowsUpdate
	Add-WUServiceManager -MicrosoftUpdate
	Install-WindowsUpdate -MicrosoftUpdate -AcceptAll 
	Write-Output "You can visit https://www.techrepublic.com/article/how-to-use-powershell-to-manage-microsoft-updates-on-windows/ if you want to learn more..."
	cont
    


}

function firewall {

}

function regconfig {

}

function userconfig {

	Write-Output "Do you have all user configurations written down?"
	cont
	Write-Output "Do you need to add users to the system? y or n"
	$addyn = Read-Host
	if ($addyn -eq "y") {
	
		$adduserslist = (Read-Host "List all users you want to add with a space in between.").split(" ") | %{$_.trim()}
		for ($i=0; $i -lt $adduserslist.length; $i++) {
			clear
			New-LocalUser -Name $adduserslist[$i] -Description "Wanted in readme" -NoPassword
			Write-Output User $adduserslist[$i] has been added
		}
	}
	
	Cont
	$usersonthiscomp = (Read-Host "List all users on this computer (separated by comma)").split(" ") | %{$_.trim()}
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

function passwordpol {

}

function audits {

}

function removeprograms {
	
	#List of installed programs
	Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName > ~/Desktop/installedprograms.txt

	
	for i in $(type ~/Desktop/installedprograms.txt)
	do
		Write-Output "The program $i is installed"
	done
		$programs = (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName).Name
	ForEach($i in ~/Desktop/installedprograms.txt) {
		Write-Output The program $i is installed
	}
}
}

runAll
