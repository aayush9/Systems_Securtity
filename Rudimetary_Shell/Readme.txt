The server makes use of pthreads to keep track of clients and handle their connections, while the client code is just a loop which takes input, and sends to the server and displays output it received from it.
The server uses pthreads so as to serve the clients simultaneously (not halt as recv is a blocking call).
The server listens to the socket, and on getting a message, tokenizes and compares to the list of given function, if some of them matches, the corresponding function is invoked. The corresponding function populates a string, output, which is sent back to the client to be displayed to the user.

Functions:
	- ls: Uses opendir and readdir to list the files, and along with fstat displays the user and group associated with the file or directory
	- cd: Uses the chdir call to change the working directory. The server notes down the change into an array (current directory of each user)
	- fput: Uses fopen to open the file in append mode and puts the given line into the file. Only the owner is able to do this operation
	- fget: Uses fopen and prints contents of the file to console (of client). Only owner or group can do this operation
	- create_dir: Tokenizes the given path, and traverses it token by token, if the directory is not present, it creates it iteratively (uid,gid same as parent directory)

	The above functions are carried out in context to the user, like if a relative path is given, the server chdir's into the current_directory of the user, and then does the operation

Assumption:
	- None of the commands have any command line flags
	- Usernames are only of type u1, u2,..., and none of them require passwords to login.
	- A user can be logged in from one instance at a time
	- fput appends only 1 line to the file. If the user wants to write multiple lines, he/she has to call the fput function multiple times
	- server should run as sudo, due to handling of the file permissions in the filestat itself
	- Paths can either be absolute or relative to the current working directory

System Calls:
	- opendir(), closedir()
	- readdir()
	- mkdir()
	- stat()
	- getcwd()
	- chdir()
	- chown()

Attacks:
	- Denial of Service, so as to not overwhelm the server with connection requests, the server sleeps for a few microseconds if an invalid credential is given
	- Escape out of directory tree, the server doesn't allow clients to go or do actions outside the /, or simple_slash
	- Buffer overflow, the input is validated so as to ensure that atleast one character at the end of the input string is 0, or not touched by the input, lest a buffer overflow attack is attempted and exit the program.