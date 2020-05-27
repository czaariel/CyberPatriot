# Linux Checklist

## Notes

When you see `$word` do not type it as is, replace it with what the variable is asking.
#### Related to the script
        Please note unauthorized use of this may result in disqualification from CyberPatriot competition
        Write down all passwords and answer forensics questions BEFORE running this script

        Important:
        1) Read the read me to check what users need to be added/removed and whose password needs to be changed
        2) Make sure to write down all forensics questions and points earned incase the script messes up
         3) Check the users and replace them into the variables located near the password and userchange function function 
         4) Check all capitalization and spelling
         5) Use "sudo bash linuxscript.sh" to run file when ready
         6) NOTES: ADD A MENU FOR SCRIPT!; ADD 


## Checklist

1. Read the README (2 times: once before Forensics Questions, once after you read them)

1. Do the Forensics Questions
	
        1. Help with 



1. If Script fails do this; if it works, go to step 4.

	1. Configure Updates and Install Clamav
		
                ````
                sudo add-apt-repository -y ppa:libreoffice/ppa
                sudo apt-get update -y -qq
                sudo apt-get upgrade -y -qq
                sudo apt-get dist-upgrade -y -qq
                sudo apt-get gksu -y -qq
                sudo apt-get install p7zip-full
                ````
                
                ````
                killall firefox -y -qq
                sudo apt-get --purge --reinstall install firefox -y -qq
                sudo apt-get install clamav clamav-daemon -y -qq
                clamscan --version
                ````
	1. User Management
		
		If you want to add a user, do: 
			
			````
                        sudo useradd $theuseryouwanttoadd
                        sudo mkdir /home/$theuseryouwanttoadd
                        sudo chown $theuseryouwanttoadd /home/$theuseryouwanttoadd
			sudo chgrp $theuseryouwanttoadd /home/$theuseryouwanttoadd
			````
                        
                If you want to delete a user do: `userdel -r $userthatyouwanttodelete`
                
                If you want to make a user an admin do: 
                	
                        ````
                        gpasswd -a $userthatneedsadmin sudo
		        gpasswd -a $userthatneedsadmin adm
			gpasswd -a $userthatneedsadmin lpadmin
			gpasswd -a $userthatneedsadmin sambashare
                        ````

                If you want to make a user a normal user do:
                	
                        ````                
                        gpasswd -a $userthatneedsadmin sudo
		        gpasswd -a $userthatneedsadmin adm
			gpasswd -a $userthatneedsadmin lpadmin
			gpasswd -a $userthatneedsadmin sambashare    
                        ````

                Once you are done with that, to configure passwords, you can do:
                
                `sudo echo -e 'CyberPatri0t!\nCyberPatri0t!' | sudo passwd $userthatneedsanewpassword`
                
                        
1. Secure root

        set `PermitRootLogin no` in `/etc/ssh/sshd_config`
    
    
              In order to gain ownership of the file, you can do:


              ````
              sudo chown $whoyouareloggedinas /etc/ssh/sshd_config
              gedit /etc/ssh/sshd_config
              ````


1. Secure Users

        1. Disable the guest user
              
              Go to `/etc/lightdm/lightdm.conf` and add the line
              
              `allow-guest=false`
              
        1. Open up `/etc/passwd` and check which users
                * Are uid 0
                * Can login
                * Are allowed in the readme
        1. Delete unauthorized users:
        
                `sudo userdel -r $userthatshouldbedeleted`
                
                `sudo groupdel $userthatshouldbedeleted`
                
        1. Check `/etc/sudoers.d` and make sure only members of the group sudo can sudo
        
        
        
        
        
        
        
        
        
        
        
        
