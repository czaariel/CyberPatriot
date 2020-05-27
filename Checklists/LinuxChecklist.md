# Linux Checklist

## Notes

When you see `$word` do not type it as is, replace it with what the variable is asking.

**Related to the Script**

Please note unauthorized use of this may result in disqualification from CyberPatriot competition
	
Write down all passwords and answer forensics questions BEFORE running this script

***Important***

Read the read me to check what users need to be added/removed

Make sure to write down all forensics questions answers and points earned incase the script messes up

Save the file with a `.sh` ending. Example: `linuxscript.sh`

Check all capitalization and spelling

Use "sudo bash linuxscript.sh" to run file when ready

You will have to be in the right directory to run. For example, if the script is saved on the desktop, you have to use `cd /home/$currentuser/Desktop`


## Checklist

1. Read the README (2 times: once before Forensics Questions, once after you read them)

1. Do the Forensics Questions
	
        1. Help with 



1. If the script works, then skip to step 4, otherwise, do this step!

	1. Configure Updates and Install Clamav
		
		````
		sudo add-apt-repository -y ppa:libreoffice/ppa
		sudo apt-get update -y -qq
		sudo apt-get upgrade -y -qq
		sudo apt-get dist-upgrade -y -qq
		sudo apt-get gksu -y -qq
		sudo apt-get install p7zip-full

		killall firefox -y -qq
		sudo apt-get --purge --reinstall install firefox -y -qq
		sudo apt-get install clamav clamav-daemon -y -qq
		clamscan --version
		````
		
	1. User Management
		
		1. If you want to add a user, do:
			
			````			
			sudo useradd $theuseryouwanttoadd
			sudo mkdir /home/$theuseryouwanttoadd
			sudo chown $theuseryouwanttoadd /home/$theuseryouwanttoadd
			sudo chgrp $theuseryouwanttoadd /home/$theuseryouwanttoadd
			````
                        
		1. If you want to delete a user do: `userdel -r $userthatyouwanttodelete`
                
		1. If you want to make a user an admin do: 
                	
			````
			gpasswd -a $userthatneedsadmin sudo
			gpasswd -a $userthatneedsadmin adm
			gpasswd -a $userthatneedsadmin lpadmin
			gpasswd -a $userthatneedsadmin sambashare
			````

		1. If you want to make a user a normal user do:
                	
			````                
			gpasswd -a $userthatneedsadmin sudo
			gpasswd -a $userthatneedsadmin adm
			gpasswd -a $userthatneedsadmin lpadmin
			gpasswd -a $userthatneedsadmin sambashare    
			````

		1. Once you are done with that, to configure passwords, you can do:
                
			`sudo echo -e 'CyberPatri0t!\nCyberPatri0t!' | sudo passwd $userthatneedsanewpassword`
	1. Password Policies
	
		1. Gain control of the file by typing `sudo chown $whoyouareloggedinas /etc/pam.d/common-password`. Then type `gedit /etc/pam.d/common-password`
		
		
		1. Password History
			
			To change the password history, add `remember=5` to the end of the line with `pam_unix.so`
			
		1. Password length
		
			To change the password length, add `minlen=10` to the end of the line with `pam_unix.so`

		1. Complexity Requirements
		
			To change the complexity requirements, add `ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1` to the end of the line with `pam_cracklib.so`
			If `pam_cracklib.so` is not found, type: `sudo apt-get install libpam-cracklib`

	1. Account Policies
	
		1. Gain control of the file by typing `sudo chown $whoyouareloggedinas /etc/login.defs`. Then type `gedit /etc/login.defs`. 
				
		1. Change `PASS_MAX_DAYS to 90`, `PASS_MIN_DAYS to 10`, and `PASS_WARN_AGE to 7`.
                
		1. Gain control of the next file by typing `sudo chown $whoyouareloggedinas /etc/pam.d/common-auth`. Then do `gedit /etc/pam.d/common-auth`
		
		1. Add the following to the end of the file: `auth required pam_tally2.so deny 5 onerr=fail unlock_time=1800`
		
	1. Audit Policies
		
		1. To Install and turn on audits, type:
		
			````
			sudo apt-get install auditd
			auditctl -e 1
			````
		
		1. If you need to configure the audits: `gedit /etc/audit/auditd.conf`
		
	1. Disable Root and Guest login
		
		1. Disable root
		
			First type: `sudo apt-get install openssh-server`
			
			Then use `sudo systemctl status ssh` to make sure it is working.
			
			Take control of the file: `sudo chown $whoyouareloggedinas /etc/ssh/sshd_config`
			
			Open the file using `gedit /etc/ssh/sshd_config`
			
			Change `PermitRootLogin` to `no`

		1. Disable Guest
		
			First type: `sudo chown $whoyouareloggedinas /etc/lightdm/lightdm.conf
			
			Then edit file using `gedit /etc/lightdm/lightdm.conf`
			
			Add `allow-guest=false` into the file
			
	1. Remove harmful programs
		
		1. Remove specific apps
		
			````
			sudo apt-get remove --purge wireshark
			sudo apt-get autoremove
			````
			
		1. Remove Default Games
		
			````
			sudo apt-get purge gnome-games-common gbrainy && sudo apt-get autoremove
			sudo apt-get remove aisleriot gnome-mahjongg gnome-mines gnome-sudoku
			````
			
		1. Remove Nmap and Zenmap
		
			````
			sudo apt-get remove nmap
			sudo apt-get purge nmap
			sudo apt-get remove zenmap
			sudo apt-get purge zenmap
			````
			
		1. Disable Telnet
		
			````
			ufw deny telnet
			ufw deny rtelnet
			ufw deny telnets
			apt-get purge telnet -y 
			apt-get purge telnetd -y
			apt-get purge inetutils-telnetd -y
			apt-get purge telnet-ssl -y
			````
			
	1. Firewall Configurations
	
		````
		sudo apt-get install ufw -y
		sudo apt-get upgrade ufw -y
		sudo ufw enable
		sysctl -n net.ipv4.tcp_syncookies
		echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
		echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
		````
		
	1. File Configs (MAKE SURE ALL FORENSICS QUESTIONS ARE COMPLETED)
	
		In order to delete all instances of a file, you can use: 
		
		````
		sudo find / -name '*.$fileending' -type f -delete
		````
		
		or
		
		````
		sudo rm -rf *.$fileending
		````
		
		For example, to delete all mp3 files, you can use `sudo rm -rf *.mp3` or `sudo find / -name '*.mp3' -type f -delete`
		
1. 

			

                        
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
        
        
        
        
        
        
        
        
        
        
        
        
