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


runAll
	

	
