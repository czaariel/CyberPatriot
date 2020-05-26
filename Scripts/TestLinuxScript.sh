
#!/bin/bash

##Create a function to be able to decide to move on or not...
cont() {
  echo "Continue (Y | N)?"
  read contyn
  if [ "$contyn" = "N" ] || [ "$contyn" = "n" ]
  then
		echo "Exiting"
    exit
  fi
	clear
}



##Update programs and systems
updates() {
	sudo add-apt-repository -y ppa:libreoffice/ppa
	sudo apt-get update -y
	wait
	sudo apt-get upgrade -y
	wait
	sudo apt-get dist-upgrade -y
	wait
	killall firefox
	wait
	sudo apt-get --purge --reinstall install firefox
	wait
	sudo apt-get gksu
	##Enable autoupdates
	sudo apt-get install unattended-upgrades
	echo "Next step will enable unattended upgrades... press yes to make sure it works. Also make sure to get rid of // to enable all autoupdates"
	cont
	sudo dpkg-reconfigure --priority=low unattended-upgrades
	nano /etc/apt/apt.conf.d/50unattended-upgrades
	echo "automatic updates configured, visit settings to make sure"
	cont
	##Install clamav
	echo "installing clamav"
	sudo apt-get install clamav clamav-daemon
	clamscan --version
	echo "done installing clamav"
	cont
	##Update 7-Zip
	sudo apt-get install p7zip-full

}

##Look at ports and which aplications are using them
netstats() {
	##Check for listening ports
	lsof -i -n -P
	netstat -tulpn
	cont
}

fastusrchg() {
	#Welcome and user listing
	clear
	echo "Please go and make sure you have all of the users properties that you need to change!"
	cont
	
	echo "Do you need to add any users to the system?"
	read addyn
	if [ "$addyn" = "Y" ] || [ "$addyn" = "y" ]
	then
		echo "Please list all users you need to add with a space in between them... ex: tom bob joe"
		read -a needaddusers
		
		needaddusersLength=${#needaddusers[@]}
		
		for (( i=0;i<$needaddusersLength;i++))
		do
			clear
			echo ${needaddusers[${i}]}
			sudo useradd ${needaddusers[${i}]}
			sudo mkdir /home/${needaddusers[${i}]}
			sudo chown ${needaddusers[${i}]} /home/${needaddusers[${i}]}
			sudo chgrp ${needaddusers[${i}]} /home/${needaddusers[${i}]}
			echo Finished creating user ${needaddusers[${i}]}
		done
	else
		echo "Moving on"
		clear
	fi

	echo "Please list all users on the system with a space in between... ex: tom bob joe"
	read -a users
	
	usersLength=${#users[@]}
	
	for (( i=0;i<$userLength;i++))
	do
		clear
		echo ${users[${i}]}
		echo Delete ${users[${i}]}? (Y|N)
		read deleteyn
		if [ "$deleteyn" = "Y" ] || [ "$deleteyn" = "y" ]
		then
			userdel -r ${users[${i}]}
			echo ${users[${i}]} has been deleted.
		else
			echo Make ${users[${i}]} administrator? (Y|N)
			read adminyn
			if [ "$adminyn" = "Y" ] || [ "$adminyn" = "y" ]
			then
				gpasswd -a ${users[${i}]} sudo
				gpasswd -a ${users[${i}]} adm
				gpasswd -a ${users[${i}]} lpadmin
				gpasswd -a ${users[${i}]} sambashare
				echo ${users[${i}]} is now an admin.
			else 
				gpasswd -d ${users[${i}]} sudo
				gpasswd -d ${users[${i}]} adm
				gpasswd -d ${users[${i}]} lpadmin
				gpasswd -d ${users[${i}]} sambashare
				gpasswd -d ${users[${i}]} root
				echo ${users[${i}]} is now a standard user.
			fi
			
			clear
			echo Changing password for ${users[${i}]}.
			sudo echo -e 'CyberPatri0t!\nCyberPatri0t!' | sudo passwd ${users[${i}]}
			echo Done changing password for ${users[${i}]}.
			
		fi
	done
	clear
	
	
			
}

passwordConf() {
	##Set Password History
	chown $loggedinas /etc/pam.d/common-password
	chown $loggedinas /etc/pam.d/common-password
	chown $loggedinas /etc/pam.d/common-password
	echo "Change password history to 5 by adding 'remember=5' to the end of the line with pam_unix.so"
	cont
	gedit /etc/pam.d/common-password
	echo "Done editing password history?"
	cont
	echo "Add password length of 10 to end of line with pam_unix.so by using minlen=10 "
	cont
	echo "done?"
	cont
	echo "add ucredit=-1 1credit=-1 dcredit=-1 ocredit=-1 to the end of line with pam_cracklib.so "
	echo "Done with all password configuration?"
	cont
	echo "Moving onto account policy..."
	echo "Add the following to the end of the file: auth required pam_tally2.so deny 5 onerr=fail unlock_time=1800   "
	cont
	gedit /etc/pam.d/common-auth
	echo "done?"
	cont
	echo "setting password aging..."
	echo "change PASS_MAX_DAYS to 90, PASS_MIN_DAYS to 10, and PASS_WARN_AGE to 7. save and close file..."
	cont
	gedit /etc/login.defs
	cont


	echo "Done with password restrictions, account policy, and audits. Move on to disabling root and guest login?"
	cont	
}

auditpolicies() {
	##turn on audits
	sudo apt-get install auditd
	auditctl -e 1	
	##Audit settings
	echo "Want to change audit settings? (Y|N)"
	read chgaudit
	if [ "$chgaudit" = "Y" ] || [ "$chgaudit" = "y" ]
	then
		echo "Opening audit settings..."
		gedit /etc/audit/auditd.conf
	fi
}

##Disable root login and guest
disrootandguest() {
	##Disabling root
		#Get file perms
		chown $loggedinas /etc/ssh/sshd_config
	echo "Disabling root login..."
	echo "If you want to disable root, change PermitRootLogin to no"
	cont
	gedit /etc/ssh/sshd_config
	echo "Done disabling root"
	cont
	##Disable Guest access
		#Get file perms
		chown $loggedinas /etc/ssh/sshd_config
	echo "disabling guest access"
	echo "add the following: allow-guest=false into the file"
	sudo gedit /etc/lightdm/lightdm.conf
	echo "Done disabling guest access"
	cont
}

removethese() {
	##Remove WireShark
	echo  "Removing wireshark IF installed..."
	sudo apt-get remove --purge wireshark
	apt-get autoremove
	echo "Done removing wireshark"
	cont
	##Remove apache2
	echo "Removing apache2 IF installed..."
	sudo apt-get remove --purge apache2
	apt-get autoremove
	echo "Done removing apache2"
	cont
	##Remove games
	echo "Removing default games IF installed..."
	sudo apt-get purge gnome-games-common gbrainy && sudo apt-get autoremove
	sudo apt remove aisleriot gnome-mahjongg gnome-mines gnome-sudoku 
	##Remove nmap and zenmap
	sudo apt-get remove nmap
	wait
	sudo apt-get purge nmap
	wait
	sudo apt-get remove zennmap
	wait
	sudo apt-get purge zenmap
	wait
	sudo apt-get install auditd
	wait
	echo 'Want to disable telnet? (Y|N)'
	read telnetyn
	if [ "$telnetyn" = "y" ] || [ "$telnetyn" = "Y" ]
	then
		ufw deny telnet
		ufw deny rtelnet
		ufw deny telnets
		apt-get purge telnet -y -qq
		apt-get purge telnetd -y -qq
		apt-get purge inetutils-telnetd -y -qq
		apt-get purge telnet-ssl -y -qq
		echo 'Telnet has been blocked on firewall and removed.'
	elif [ "$telnetyn" = "n" ] || [ "$telnetyn" = "n" ]
	then
		ufw allow telnet
		ufw allow rtelnet
		ufw allow telnets
		echo 'Telnet has been enabled.'
	else
		echo 'Unclear Response'
	fi
		

}

firewallconfig() {
	echo "setting up firewall"
	##Install UFW incase
	sudo apt-get install ufw -y
	##Update firewall
	sudo apt-get upgrade ufw -y
	##Turn on firewall
	sudo ufw enable
	##Enable syn cookie protection
	sysctl -n net.ipv4.tcp_syncookies
	##Disable IPv6
	echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
	##Disable IP forwarding
	echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
	##Prevent IP spoofing
	echo "nospoof on" | sudo tee -a /etc/host.conf
	echo "Done setting up firewall"
}


newtestfunc() {
	echo 'Skip'
	
}


iptablesconfig() {
	#Backup
	mkdir /iptables/
	touch /iptables/rules.v4.bak
	touch /iptables/rules.v6.bak
	iptables-save > /iptables/rules.v4.bak
	ip6tables-save > /iptables/rules.v6.bak
	#Clear out and default iptables
	iptables -t nat -F
	iptables -t mangle -F
	iptables -t nat -X
	iptables -t mangle -X
	iptables -F
	iptables -X
	iptables -P INPUT DROP
	iptables -P FORWARD DROP
	iptables -P OUTPUT ACCEPT
	ip6tables -t nat -F
	ip6tables -t mangle -F
	ip6tables -t nat -X
	ip6tables -t mangle -X
	ip6tables -F
	ip6tables -X
	ip6tables -P INPUT DROP
	ip6tables -P FORWARD DROP
	ip6tables -P OUTPUT DROP
	#Block Bogons
	printf "\033[1;31mEnter primary internet interface: \033[0m\n"
	read interface
	#Blocks bogons going into the computer
	iptables -A INPUT -s 127.0.0.0/8 -i $interface -j DROP
	iptables -A INPUT -s 0.0.0.0/8 -j DROP
	iptables -A INPUT -s 100.64.0.0/10 -j DROP
	iptables -A INPUT -s 169.254.0.0/16 -j DROP
	iptables -A INPUT -s 192.0.0.0/24 -j DROP
	iptables -A INPUT -s 192.0.2.0/24 -j DROP
	iptables -A INPUT -s 198.18.0.0/15 -j DROP
	iptables -A INPUT -s 198.51.100.0/24 -j DROP
	iptables -A INPUT -s 203.0.113.0/24 -j DROP
	iptables -A INPUT -s 224.0.0.0/3 -j DROP
	#Blocks bogons from leaving the computer
	iptables -A OUTPUT -d 127.0.0.0/8 -o $interface -j DROP
	iptables -A OUTPUT -d 0.0.0.0/8 -j DROP
	iptables -A OUTPUT -d 100.64.0.0/10 -j DROP
	iptables -A OUTPUT -d 169.254.0.0/16 -j DROP
	iptables -A OUTPUT -d 192.0.0.0/24 -j DROP
	iptables -A OUTPUT -d 192.0.2.0/24 -j DROP
	iptables -A OUTPUT -d 198.18.0.0/15 -j DROP
	iptables -A OUTPUT -d 198.51.100.0/24 -j DROP
	iptables -A OUTPUT -d 203.0.113.0/24 -j DROP
	iptables -A OUTPUT -d 224.0.0.0/3 -j DROP
	#Blocks outbound from source bogons - A bit overkill
	iptables -A OUTPUT -s 127.0.0.0/8 -o $interface -j DROP
	iptables -A OUTPUT -s 0.0.0.0/8 -j DROP
	iptables -A OUTPUT -s 100.64.0.0/10 -j DROP
	iptables -A OUTPUT -s 169.254.0.0/16 -j DROP
	iptables -A OUTPUT -s 192.0.0.0/24 -j DROP
	iptables -A OUTPUT -s 192.0.2.0/24 -j DROP
	iptables -A OUTPUT -s 198.18.0.0/15 -j DROP
	iptables -A OUTPUT -s 198.51.100.0/24 -j DROP
	iptables -A OUTPUT -s 203.0.113.0/24 -j DROP
	iptables -A OUTPUT -s 224.0.0.0/3 -j DROP
	#Block receiving bogons intended for bogons - Super overkill
	iptables -A INPUT -d 127.0.0.0/8 -i $interface -j DROP
	iptables -A INPUT -d 0.0.0.0/8 -j DROP
	iptables -A INPUT -d 100.64.0.0/10 -j DROP
	iptables -A INPUT -d 169.254.0.0/16 -j DROP
	iptables -A INPUT -d 192.0.0.0/24 -j DROP
	iptables -A INPUT -d 192.0.2.0/24 -j DROP
	iptables -A INPUT -d 198.18.0.0/15 -j DROP
	iptables -A INPUT -d 198.51.100.0/24 -j DROP
	iptables -A INPUT -d 203.0.113.0/24 -j DROP
	iptables -A INPUT -d 224.0.0.0/3 -j DROP
	iptables -A INPUT -i lo -j ACCEPT
	#Least Strict Rules
	#iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	#Strict Rules -- Only allow well known ports (1-1022)
	#iptables -A INPUT -p tcp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	#iptables -A INPUT -p udp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -p tcp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -p udp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -o lo -j ACCEPT
	#iptables -P OUTPUT DROP
	#Very Strict Rules - Only allow HTTP/HTTPS, NTP and DNS
	iptables -A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -o lo -j ACCEPT
	iptables -P OUTPUT DROP
	mkdir /etc/iptables/
	touch /etc/iptables/rules.v4
	touch /etc/iptables/rules.v6
	iptables-save > /etc/iptables/rules.v4
	ip6tables-save > /etc/iptables/rules.v6
	cont
}

filesconfig() {
	echo "deleting unwanted files..."
	find / -name '*.mp3' -type f -delete
	find / -name '*.mov' -type f -delete
	find / -name '*.mp4' -type f -delete
	find / -name '*.avi' -type f -delete
	find / -name '*.mpg' -type f -delete
	find / -name '*.mpeg' -type f -delete
	find / -name '*.flac' -type f -delete
	find / -name '*.m4a' -type f -delete
	find / -name '*.flv' -type f -delete
	find / -name '*.ogg' -type f -delete
	find /home -name '*.gif' -type f -delete
	find /home -name '*.png' -type f -delete
	find /home -name '*.jpg' -type f -delete
	find /home -name '*.jpeg' -type f -delete
}

startingmenu() {
	clear
	echo "

	  ---------------------------------------------------------------------------------
	  Welcome to the Raleigh-Wake CyberPatriot Linux script, choose a number (1-10):
	      1) General Updates
	      2) Network Statistics
	      3) User Configurations
	      4) Password Configurations
	      5) Disable Root and Guest accounts
	      6) Audit Policies
	      7) Remove Programs
	      8) Firewall Config
	      9) *test function, please skip this*
	      10) IP table configuration
	      11) File Configuration
	  ---------------------------------------------------------------------------------
	"
	read pleasegoto

	if [ "$pleasegoto" = "1" ] || [ "$pleasegoto" = "one" ]
	then
	    updates
	    startingmenu
	elif [ "$pleasegoto" = "2" ] || [ "$pleasegoto" = "two" ]
	then
	    netstats
	    startingmenu
	elif [ "$pleasegoto" = "3" ] || [ "$pleasegoto" = "three" ]
	then
	    fastusrchg
	    startingmenu
	elif [ "$pleasegoto" = "4" ] || [ "$pleasegoto" = "four" ]
	then
	    passwordConf
	    startingmenu
	elif [ "$pleasegoto" = "5" ] || [ "$pleasegoto" = "five" ]
	then
	    disrootandguest
	    startingmenu
	elif [ "$pleasegoto" = "6" ] || [ "$pleasegoto" = "six" ]
	then
	    auditpolicies
	    startingmenu
	elif [ "$pleasegoto" = "7" ] || [ "$pleasegoto" = "seven" ]
	then
	    removethese
	    startingmenu
	elif [ "$pleasegoto" = "8" ] || [ "$pleasegoto" = "eight" ]
	then
	    firewallconfig
	    startingmenu
	elif [ "$pleasegoto" = "9" ] || [ "$pleasegoto" = "nine" ]
	then
	    echo "please rerun, the number 9 function is not currently working." #newtestfunc
	elif [ "$pleasegoto" = "10" ] || [ "$pleasegoto" = "ten" ]
	then
	    iptablesconfig
	    startingmenu
	elif [ "$pleasegoto" = "11" ] || [ "$pleasegoto" = "eleven" ]
	then
	    filesconfig
	    startingmenu
	fi
}

startingmenu


