Can run this practical on one computer or on multiple computers:

***--- One Computer ---***
****************************
SETUP
****************************
Make sure the .class files in the bin/ folders of both Client, Client1, Client2 and Server can be run with:
java <Name of .class file without .class extension>

If not:
Recompile them from their respective src/ folders and move the compiled file into the bin/ folder with:
javac <Name of .java file with .java extension>

****************************
RUNNING SIMULATION
****************************
Open 3 Command line prompts in the following path:
bin/ folder of Client 1 - Client1/bin/
bin/ folder of Client 2 - Client2/bin/
bin/ folder of Server - Server/bin/

Start running the Server first:
Go to the command prompt with the path Server/bin/ and run:
java TcpServer

This will start running the server ** note the IP address and port number the server is running on.

Start running the Clients:
Go to the command prompt of either Client 1 or Client 2's path - Client1/bin/ or Client2/bin/.

Run:
java TcpClient <noted IP address> <noted Port number>


This runs the client and the client will be able to send secured messages to the server within the command prompt.
Run:
java TcpClient <noted IP address> <noted Port number>

On the other command prompt you haven't done so yet.
Once this has connected to the server, you should have 2 clients connected to the server.
Type your message and follow the debug/trace statements.

To exit:
type "!!exit" as the message.
Lastly Ctrl+C the server.

****************************
RUNNING WITH NEW CLIENT
****************************
Go to the client folder, into the bin folder.
Firstly we need to create an RSA key pair for the new client.
Open command prompt in the Client/bin/ folder.
Run:
java RSAKeyGenerator <Enter unique Key ID> <Enter Prefix of filename - anything>

This will generate an RSA key pair and save the public key and private key in separate textfiles.
You will find these files in the bin folder.

Copy and paste the private key contents into EncryptionPrivate.txt - override the contents within EncryptionPrivate.txt.
Copy and paste the public key contents into GlobalPublic.txt - append the copied content into GlobalPublic.txt.
Update all GlobalPublic.txt files in the other application folders - Client1, Client2, Server.

Now in the command prompt with the path Client/bin/ run:
java TcpClient <noted IP address> <noted Port number>

***--- Multiple Computers ---***
Ran the same way as with 1 computer. The only difference is the way the folder applications are distributed:
The computer running the server should only have the Server folder.
The computer running Client 1 should only have the Client1 folder.
The computer running Client 2 should only have the Client2 folder.

Run everything in command prompt as detailed above for one computer.
If the third client is setup - generated RSA key pair and updated GlobalPublic.txt,
You can run another computer with the Client folder.

****************************
If any issues arise or a demo is required, please email gxxhen001@myuct.ac.za.
