Assumptions: 
	None

Shellcode:
	The program consists of a write (to stdout) syscall, and an exit syscall. A jump trick is used so the string is actually pushed to the stack, and is later popped, instead of moving which may cause null characters.

How to execute:
	Use the compile.sh script to build the object file of the shellcode, and then the python script calls an objdump on it, and parses the output in a format that can be passed to the victim program as an input.

bash compile.sh
python gen.py | ./victim
