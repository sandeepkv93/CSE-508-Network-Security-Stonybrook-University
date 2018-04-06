Plugboard Proxy

**********************
Sandeep Kumta Vishnu
SBU ID: 111482809
**********************

How to Build the Program!
*************************
1. First of all, inorder to compile 'libssl' should be installed. To install it, execute
	$ sudo apt-get install libssl-dev

2. After it is installed, create pbproxy binary by executing 'make' command
	$ make

How to Run the Program!
************************
Constraint: SSHD should be running and the port has right permission.

Test Case 1:
1. In the first machine, execute the following command
	$ ./pbproxy -k mykey -l 2222 localhost 22

2. In the second machine, execute the following command
	$ ssh -o "ProxyCommand ./pbproxy -k mykey localhost 2222" localhost

	It will prompt for the password. Once entered, able to ssh into it successfully.

Test Case 2:
1. In the first machine, execute the following command
	$ ./pbproxy -k mykey -l 2222 localhost 22

2. In the second machine, execute the following command
	$ ssh -o "ProxyCommand ./pbproxy -k mykey localhost 2222" localhost

	It will prompt for the password. Once entered, able to ssh into it successfully.

3. In the third machine, execute the following command
	$ ssh -o "ProxyCommand ./pbproxy -k mykey localhost 2222" localhost

	It will wait. Once, the ssh connection from second machine exits, password prompt 
	will be appeared in third machine and once entered, able to ssh into it successfully.

	By this, it is proved that the server will not exit after one connect exits and it continously 
	waits for the new connection.


Files in the Program!
**********************
The program is completely modularized where the functionalities of cryptography related stuffs, server, 
client and proxy related functionalities are separated in different files, namely

C Files:
1. crypto.c ===> Encryption and Decryption Functionalities.
2. pbclient.c ===> Client related Functionalities.
3. pbproxy.c  ===> Proxy related Functionalities (This also has the main function).
4. pbserver.c ===> Server related Functionalities.

Header Files: header files for the above C file containing the declaration of respective functions.
1. crypto.h
2. pbclient.h
3. pbproxy.h
4. pbserver.h

Make File which successfully builds all these files and creates a binary 'pbproxy'


Implementation!
***************

Client Side:
1. In client mode, I use a infinite loop to try reading from the standard input and the socket. 
2. I set them to non-blocking non blocking mode. 
3. When I recieve data from standard input I encrypt data and send it to server via socket
4. When I recieve data from socket, write to standard output.

Server Side:
1. Server listens for input connection in its listening port
2. Once, a connection is requested, the request is sent to the service handler who will establish a TCP socket with the SSH port.
3. Server montiors sockets with accepted connection and also SSH socket.
4. Once a connection is exited, server continues to wait for the new connection.

Cryptography:
1. when client proxy gets some data from standard input, it will encrypt it and send it to server proxy who will decrypt it before fowrwarding it to ssh socket. 
2. Different IV is used for each mesage exachange.
3. IV is attached to the message and it will be extracted before we decrypt the encrypted message.


References
************
(A) SSH Related
	1. https://www.cyberciti.biz/faq/howto-start-stop-ssh-server/'
	2. https://security.stackexchange.com/questions/124767/what-could-cause-bad-packet-length-with-sshd

(B) Socket Programming
	1. http://www.cs.rpi.edu/~moorthy/Courses/os98/Pgms/socket.html
	2. https://stackoverflow.com/questions/6729366/what-is-the-difference-between-af-inet-and-pf-inet-in-socket-programming
	3. https://stackoverflow.com/questions/7483510/in-which-cases-is-calling-bind-necessary
	4. https://stackoverflow.com/questions/14485517/why-does-fd-isset-return-true-after-select

(C) Encryption-Decryption
	1. https://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl
	2. https://stackoverflow.com/questions/20039066/aes-ctr128-encrypt-string-and-vice-versa-ansi-c

(D) Man Pages
	1. http://man7.org/linux/man-pages/man2/select.2.html
	2. http://man7.org/linux/man-pages/man2/bind.2.html
	3. http://man7.org/linux/man-pages/man2/listen.2.html
	4. https://linux.die.net/man/3/fd_set

