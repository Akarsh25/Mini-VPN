# Mini-VPN

Simple TLS/SSL VPN which exemplified number of security principles including the following:
* TUN/TAP and IP tunnelling
* Routing
* Public key cryptography
* TLS/SSL programming
* Authentication. 

To compile the compile: 
$ make 

To run the server: 
$ sudo ./tlsserver

To run the client:
First change the SERVER_IP in tlsclient.c to match with the server's ip.  
$ sudo ./tlsclient

Note: 
* You also need to configure the TUN interfaces on both sides and set up routings.
* You need to create CA and server certiicates.
* Check lab description for configurations and more commands.

