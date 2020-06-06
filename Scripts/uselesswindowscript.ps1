Write-Output "Hello"


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

}

function passwordpol {

}

function audits {

}

function removeprograms {

}

runAll
