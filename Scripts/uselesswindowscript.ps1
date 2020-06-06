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
