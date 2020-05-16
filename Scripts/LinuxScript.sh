##Please note unauthorized use of this may result in disqualification from CyberPatriot competition
##Write down all passwords and answer forensics questions BEFORE running this script

##Important:
## 1) Read the read me to check what users need to be added/removed and whose password needs to be changed
## 2) Make sure to write down all forensics questions and points earned incase the script messes up
## 3) Check the users and replace them into the variables located near the password and userchange function function 
## 4) Check all capitalization and spelling
## 5) Use "sudo bash linuxscript.sh" to run file when ready

#!/bin/bash

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

##Create a function to run all functions, make it easier to organize
runAll() {
	clear
	
	updates
	netstats
	fastusrchg
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
	echo "setting updates"
	sudo apt-get purge gedit
	sudo apt-get install gedit
	##Start with firefox
	killall firefox
	wait
	sudo apt-get update
	sudo apt-get --purge --reinstall install firefox
	wait
	sudo apt-get upgrade
	sudo apt-get dist-upgrade
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
	##Remove nmap and zenmap
	sudo apt-get remove nmap
	cont
	sudo apt-get purge nmap
	cont
	sudo apt-get remove zennmap
	cont
	sudo apt-get purge zenmap
	cont
	sudo apt-get install auditd
	cont
}

##Look at ports and which aplications are using them
netstats() {
	##Check for listening ports
	lsof -i -n -P
	netstat -tulpn
	cont
}

##This is a list of variables used in if statements below... change the users to the correct usernames before running...
deleteme="Tommy"
addme="Jeremy"
chgtype="bobby"
chgtypetouser="Stephen"
fastusrchg() {
	##Delete unwanted users
	echo "need to delete any users (Y|N)?"
	read confirmdeleteusers
	if [ "$confirmdeleteusers" = "Y" ]||[ "$confirmdeleteusers" = "y"]
	then
		mkdir /oldusers-data
		chown root:root /oldusers-data
		chmod 0700 /oldusers-data
		deluser --remove-home --backup-to /oldusers-data/ $deleteme
		echo "done deleting user $deleteme"
	fi

	##Add needed users
	echo "Want to add users? (Y|N)"
	read confirmaddusers
	if [ "$confirmaddusers" = "Y" ]||[ "$confirmaddusers" = "y"]
	then
		echo "Want to make new user have sudo permissions? (Y|N)"
		read addsudos
		if [ "$addsudos" = "Y" ] || [ "$addsudos" = "y"]
		then
			useradd -s /path/to/shell -d /home/$addme -m -G sudo $addme
			echo "done adding users"
		fi
		if [ "$addsudos" = "N" ] || [ "$addsudos" = "n"]
		then
			useradd -s /path/to/shell -d /home/$addme -m -G user $addme
			echo "done adding users"
		fi
	fi
	
	##Change user types
	echo "Want to make $chgtype an administrator?(Y|N)"
	read wantadmin
	if [ "$wantadmin" = "Y" ] || [ "$wantadmin" = "y"]
	then
		echo "Changing user $chgtype an admin..."
		sudo gpasswd -a $chgtype sudo
		echo "Changed user $chgtype to admin"
	fi
	if [ "$wantadmin" = "N"] || [ "$wantadmin" = "n"]
	then
		echo "Want to make $chgtypetouser a user? (Y|N)"
		read wantuser
		if [ "$wantuser" = "Y" ] || [ "$wantuser" = "y"]
		then
			echo "Changing admin $chgtypetouser to user..."
			sudo gpasswd -d $chgtypetouser sudo
		fi
	fi
			
	##Create list of users
	echo "Please go and make a file called userlist.txt"
	cont
	##Set their passwords
	for i in $( cat userlist.txt ); do
		useradd $i
		echo "user $i added!"
		echo $i:$i"123" | chpasswd 
		##Their passwords become <username>123
	done
	echo "changed all passwords"
	cont
}

passwordConf() {
	##Set Password History
	chmod u+r /etc/pam.d/common-password
	chmod u+w /etc/pam.d/common-password
	chmod u+x /etc/pam.d/common-password
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
	sudo apt-get install auditd
	auditctl -e 1
	echo "Want to change audit settings? (Y|N)"
	read chgaudit
	if [ "$chgaudit" = "Y" ] || [ "$chgaudit" = "y"]
	then
		echo "Opening audit settings..."
		gedit /etc/audit/auditd.conf
	fi
	echo "Done with password restrictions, account policy, and audits. Move on to disabling root and guest login?"
	cont	
}

auditpolicies() {
	##turn on audits
	sudo apt-get install auditd
	auditctl -e 1
}

##Disable root login and guest
disrootandguest() {
	##Disabling root
	echo "Disabling root login..."
	echo "If you want to disable root, change PermitRootLogin to no"
	cont
	gedit /etc/ssh/sshd_config
	echo "Done disabling root"
	cont
	##Disable Guest access
	echo "disabling guest access"
	echo "add the following: allow-guest=false into the file"
	sudo gksu gedit /etc/lightdm/lightdm.conf
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

}

firewallconfig() {
	echo "setting up firewall"
	##Install UFW incase
	sudo apt-get install ufw
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
	##disable telnet
	echo "disable telnet; change disable to yes"
	cont
	gedit -w /etc/xinetd.d/telnet
	echo "done?"
	cont
	/sbin/chkconfig telnet off
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

runAll
	
