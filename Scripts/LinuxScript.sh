

#!/bin/bash

#Understand/Set basic variables
echo "Who are you logged in as? (ex: bwayne)"
read loggedinas

##Create a function to be able to decide to move on or not...
cont() {
	echo "Continue (Y | N)?"
	read contyn
	if [ "$contyn" = "N" ] || [ "$contyn" = "n"]
	then
		echo "Exiting"
	exit
	fi
	clear
}

loggedit() {

	date >> ~/Desktop/scriptlog.txt

}

##Create a function to run all functions, make it easier to organize
runAll() {
	clear
	
	updates
	networkstats
	userconfig
	passwordConf
	disrootandguest
	auditingpolicies
	removethese
	firewallconfig
	newtestfunc
	iptablesconfig
	filesconfig
	
}


##Update programs and systems
updates() {

	echo "Do you need to change the timezone? y or n"
	read timeyn
	if [ "$timeyn" = "y" ] || [ "$timeyn" = "Y" ]
	then
		timedatectl set-ntp no
		timedatectl set-timezone America/New_York
		timedatectl set-ntp yes
	fi
	clear
	echo "Starting updates and upgrades, please wait."
	sudo add-apt-repository -y ppa:libreoffice/ppa
	sudo apt-get update -y
	wait
	sudo apt-get upgrade -y
	wait
	sudo apt-get dist-upgrade -y
	wait
	killall firefox -y
	wait
	sudo apt-get --purge --reinstall install firefox -y
	wait
	sudo apt-get gksu -y
	##Enable autoupdates
	clear
	sudo apt-get install unattended-upgrades -y
	cont
	sudo dpkg-reconfigure --priority=low unattended-upgrades -y
	curl "https://raw.githubusercontent.com/czaariel/CyberPatriot/master/Scripts/UbuntuConfigFiles/unattendedupgrades.txt" -o unattendedupgrades.txt
	cp unattendedupgrades.txt /etc/apt/apt.conf.d/50unattended-upgrades
	clear
	echo "automatic updates configured, visit settings to make sure"
	cont
	##Install clamav
	echo "installing clamav"
	sudo apt-get install clamav clamav-daemon -y
	clamscan --version
	echo "done installing clamav"
	##Update 7-Zip
	sudo apt-get install p7zip-full -y
	##Install aptitude
	sudo apt-get install aptitude -y
	##Install cracklib
	sudo apt-get install libpam-cracklib
	##Install ssh
	sudo apt-get install openssh-server -y
	wait
	sudo systemctl enable ssh -y
	wait
	sudo systemctl start ssh -y
	wait
	sudo apt-get install curl -y
	clear
	echo "Done with updates and installing needed programs."
	cont
}

##Look at ports and which aplications are using them
netstats() {
	##Check for listening ports
	lsof -i -n -P
	netstat -tulpn > ~/Desktop/processes.txt
	cont
	#services
	sudo service --status-all
	cont
	#add to remove netcat
}

##This is a list of variables used in if statements below... change the users to the correct usernames before running...
userconfig() {
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
		clear
	else
		echo "Moving on"
		clear
	fi

	echo "Please list all users on the system with a space in between... ex: tom bob joe"
	read -a users
	
	usersLength=${#users[@]}
	
	for (( i=0;i<$usersLength;i++))
	do
		clear
		echo ${users[${i}]}
		echo Delete ${users[${i}]}? y or n
		read deleteyn
		if [ "$deleteyn" = "Y" ] || [ "$deleteyn" = "y" ]
		then
			userdel -r ${users[${i}]}
			echo ${users[${i}]} has been deleted.
		else
			echo Make ${users[${i}]} administrator? y or n
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
			echo Changing password of ${users[${i}]}.
			sudo echo -e 'CyberPatri0t!\nCyberPatri0t!' | sudo passwd ${users[${i}]}
			echo Done changing password of ${users[${i}]}.
			
		fi
	done
	clear
}

passwordConf() {
	
	echo "editing password policies and configurations..."
	chown $loggedinas /etc/pam.d/common-password
	chown $loggedinas /etc/pam.d/common-auth
	chown $loggedinas /etc/login.defs
	echo "password perms have been set..."
	curl "https://raw.githubusercontent.com/czaariel/CyberPatriot/master/Scripts/UbuntuConfigFiles/commonauthbackup.txt" -o commonauth.txt
	curl "https://raw.githubusercontent.com/czaariel/CyberPatriot/master/Scripts/UbuntuConfigFiles/commonpassbackup.txt" -o commonpass.txt
	curl "https://raw.githubusercontent.com/czaariel/CyberPatriot/master/Scripts/UbuntuConfigFiles/logindefsbackup.txt" -o logindefs.txt
	echo "configuration files have been downloaded from github"
	cp commonauth.txt /etc/pam.d/common-auth
	cp commonpass.txt /etc/pam.d/common-password
	cp logindefs.txt /etc/login.defs
	echo "files have been updated to match github..."
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
	chown $loggedinas /etc/ssh/sshd_config
	echo "Disabling root login..."
	sed -i '/^PermitRootLogin/s/yes/no/' /etc/ssh/sshd_config /etc/ssh/sshd_config
	echo "Done disabling root"
	##Disable Guest access
	sudo bash -c "echo '[SeatDefaults]
greeter-session=unity-greeter
user-session=ubuntu
allow-guest=false' >/etc/lightdm/lightdm.conf"
	chown $loggedinas /etc/lightdm/lightdm.conf
	echo "guest & root account has been disabled, please confirm after..."
	cont
	

}

removethese() {
	clear
	##Remove WireShark
	echo  "Removing wireshark IF installed..."
	sudo apt-get remove --purge wireshark -y -qq
	apt-get autoremove -y -qq
	echo "Done removing wireshark"
	cont
	clear
	##Remove apache2
	echo "Removing apache2 IF installed..."
	sudo apt-get remove --purge apache2 -y -qq
	apt-get autoremove -y -qq
	echo "Done removing apache2"
	cont
	clear
	##Remove games
	echo "Removing default games IF installed..."
	sudo apt-get purge gnome-games-common gbrainy && sudo apt-get autoremove -y -qq
	sudo apt remove aisleriot gnome-mahjongg gnome-mines gnome-sudoku -y -qq
	##Remove nmap and zenmap
	sudo apt-get remove nmap -y -qq
	wait
	sudo apt-get purge nmap -y -qq
	wait
	sudo apt-get remove zennmap -y -qq
	wait
	sudo apt-get purge zenmap -y -qq
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
	
	##Get a list of all non-default packeges installed and put them in file "installedbyme.txt"
	comm -23 <(apt-mark showmanual | sort -u) <(gzip -dc /var/log/installer/initial-status.gz | sed -n 's/^Package: //p' | sort -u) > /home/$loggedinas/Desktop/installedbyme.txt
	
	service -status-all > ~/Desktop/services.txt
	
	#for i in $(cat /home/$loggedinas/Desktop/installedbyme.txt)
	#do
	#	clear
	#	echo "Do you want $i installed?"
	#	read needyn
	#	if [ "$needyn" = "n" ] || [ "$needyn" = "N" ]
	#	then
	#		sudo apt-get remove --purge $i -y -qq
	#		sudo apt-get autoremove -y -qq
	#		clear
	#	else
	#		echo "keeping the file $i as stated in readme"
	#		clear
	#	fi
	#done

		

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
#	printf "\033[1;31mEnter primary internet interface: \033[0m\n"
#	read interface
	#Blocks bogons going into the computer
#	iptables -A INPUT -s 127.0.0.0/8 -i $interface -j DROP
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
#	iptables -A OUTPUT -d 127.0.0.0/8 -o $interface -j DROP
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
#	iptables -A OUTPUT -s 127.0.0.0/8 -o $interface -j DROP
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
#	iptables -A INPUT -d 127.0.0.0/8 -i $interface -j DROP
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
	echo "------------ These are the paths for the prohibited files if you need it for forensics questions..." > ~/Desktop/prohibitedFiles.txt ----------"
	echo "### mp3 files ###" >> ~/Desktop/prohibitedFiles.txt
	find / -type f -name "*.mp3" >> ~/Desktop/prohibitedFiles.txt
	echo "### mov files ###" >> ~/Desktop/prohibitedFiles.txt
	find / -type f -name "*.mov" >> ~/Desktop/prohibitedFiles.txt
	echo "### mp4 files ###" >> ~/Desktop/prohibitedFiles.txt
	find / -type f -name "*.mp4" >> ~/Desktop/prohibitedFiles.txt
	echo "### avi files ###" >> ~/Desktop/prohibitedFiles.txt
	find / -type f -name "*.avi" >> ~/Desktop/prohibitedFiles.txt
	echo "### mpg files ###" >> ~/Desktop/prohibitedFiles.txt
	find / -type f -name "*.mpg" >> ~/Desktop/prohibitedFiles.txt
	echo "### mpeg files ###" >> ~/Desktop/prohibitedFiles.txt
	find / -type f -name "*.mpeg" >> ~/Desktop/prohibitedFiles.txt
	echo "### flac files ###" >> ~/Desktop/prohibitedFiles.txt
	find / -type f -name "*.flac" >> ~/Desktop/prohibitedFiles.txt
	echo "### m4a files ###" >> ~/Desktop/prohibitedFiles.txt
	find / -type f -name "*.m4a" >> ~/Desktop/prohibitedFiles.txt
	echo "### flv files ###" >> ~/Desktop/prohibitedFiles.txt
	find / -type f -name "*.flv" >> ~/Desktop/prohibitedFiles.txt
	echo "### ogg files ###" >> ~/Desktop/prohibitedFiles.txt
	find / -type f -name "*.ogg" >> ~/Desktop/prohibitedFiles.txt
	echo "### gif files ###" >> ~/Desktop/prohibitedFiles.txt
	find / -type f -name "*.gif" >> ~/Desktop/prohibitedFiles.txt
	echo "### png files ###" >> ~/Desktop/prohibitedFiles.txt
	find / -type f -name "*.png" >> ~/Desktop/prohibitedFiles.txt
	echo "### jpg files ###" >> ~/Desktop/prohibitedFiles.txt
	find / -type f -name "*.jpg" >> ~/Desktop/prohibitedFiles.txt
	echo "### jpeg files ###" >> ~/Desktop/prohibitedFiles.txt
	find / -type f -name "*.jpeg" >> ~/Desktop/prohibitedFiles.txt
}

runAll
	
