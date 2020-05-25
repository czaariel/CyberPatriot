# Linux Checklist

## Notes

When you see `$word` do not type it as is, replace it with what the variable is asking.


## Checklist

1. Read the README (2 times: once before Forensics Questions, once after you read them)

1. Do the Forensics Questions
        1. Help with 
  
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
