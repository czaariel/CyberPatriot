# Packet Tracer Notes and Commands

##Useful Tools:
https://www.aelius.com/njh/subnet_sheet.html

## Commands and Checklist

### General Commands

   ````
   no ip domain-lookup        
   no shut                    #turns device/connection on
   show ip interfaces brief   
   show ip route              #shows ip routing table
   show run                   
   show interfaces            
   show ip interfaces         
   ````
   To enable a secret password you can
   

      ena
      conf t
      ena secret <password>


### Switches

- Configure **Default Gateway (switch) **
   ````
   ena
   conf t
   ip default-gateway [ip address]
   ````
   


### Routers
- Access Control Lists
   - Wild Card Mask
      - Can be found by subtracting 255.255.255.255 from IP subnet mask
      - Can be used to create shorter, faster commands
      - Ex: access-list 10 permit 192.168.16.0 0.0.15.255
      - Keywords: 
         - host -> substitutes for 0.0.0.0
            -  `access-list 1 permit 192.168.10.10 0.0.0.0`
            -  `access-list 1 permit host 192.168.10.10`
         - any -> substitutes for 255.255.255.255
            -  `access-list 1 permit 0.0.0.0 255.255.255.255`
            -  `access-list 1 permit any` <- are the same





### Troubleshooting

If not all packets are being received check:
   - all ports are on
   - correct mode is enabled 
      - ex: on a switch, **end devices are access** while **other devices are trunk**
   - default gateway is set and correct
   - correct encapsulation and vlan
   - make sure devices are not shutdown







## Notes

### Module 2: Network Protocols and Communications

Encoding is the process of converting information into another acceptable form, for transmission. Decoding reverses this process in order to interpret the information. Data is broken down into `frames` to make easier to handle. 

1. Protocols must account for the following requirements
    * an identified sender and receiver
    * common language and grammar
    * speed and timing of delivery
    * conformation or acknowledgement requirements
1. Message Delivery Options
    * `Unicast`: a one-to-one delivery option, meaning there is only a single destination for the message
    * `Multicast`: a one-to-many delivery of the same message to a group of host destinations simultaneously
    * `Broadcast`: one-to-all message delivery option where all hosts on the network need to receive the message at the same time
  

### Module 3: 








