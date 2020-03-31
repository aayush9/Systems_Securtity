The server makes use of pthreads to keep track of clients and handle their connections, while the client code is just a loop which takes input, and sends to the server and displays output it received from it.
The server uses pthreads so as to serve the clients simultaneously (not halt as recv is a blocking call).
The server listens to the socket, and on getting a message, tokenizes and compares to the list of given function, if some of them matches, the corresponding function is invoked. The corresponding function populates a string, output, which is sent back to the client to be displayed to the user.

The client upon startup first generates a public private key pair and tells the public key to the server.
Afterwards the client serves mostly as a remote I/O device, but with specific commands, does the encryption decryption itself where the server can't be trusted.

Functions:
	- /who: The server returns list of all usernames logged in
	- /write_all: The given message(as trailing text) is broad-casted to all the users logged in
	- /create_group: The server returns a group id and name. The group can be addressed by id in all further functions
	- /group_invite: The user mentioned is sent a notification that he has been invited to a group
	- /group_invite_accept: The user can accept invite to a group he has been invited to. The id's are assumed to be random enough that a non-invited user can't join, since he doesn't have the notification with the group id.
	- /request_public_key: A notification is sent to the other user that his public key is requested.
	- /send_public_key: The user can send the public key to others. The key is cached on their end.
	- /init_group_dhxchng: People of the group are able to derive a shared secret which they use in the write_group function
	- /write_group: Messages are written to the group, encrypted with the DH-key
	- /list_user_files: Files are listed in the directory for which owner is specified person and requester has read access.
	- /request_file: A file is requested from another user on a specific port. The responder makes a socket connection and sends the file.

Assumption:
	- Input is supposed to be present as in expected format, order of arguments etc.
	- Integers are expected to be input as integers, no typechecking on atoi is done.
	- The new file in request file is saved with a name new_file.txt, although can be changed to input name as argument, but not mentioned in problem doc...
	- If a user logs out and logs back in, all group memberships etc are lost.
	- All commands which require prior sharing of public keys, for them the public keys have to be shared before-hand, the exceptions in that case are not handled.


Attacks:
	- If users exit, the server is able to notified and apt actions are taken for groups etc.
	- Buffer overflow, the input is validated so as to ensure that atleast one character at the end of the input string is 0, or not touched by the input, lest a buffer overflow attack is attempted and exit the program.
	- After every connection request, a sleep is inserted to prevent against Denial of Service attack.