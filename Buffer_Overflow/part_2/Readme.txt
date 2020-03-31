Library base address: 0x00007ffff79e4000
Offset of execve	: 0x00000000000e4e30	

The attack was carried out following the following steps:

1) The library base address was retrieved using the ldd command.
	ldd ./victim-nonexec-stacks

2) Various gadgets were retrieved using the ROPGadget on the 
	ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 > ./LIBCgadgets

3) Address  of library retrieved by running:
	cat /proc/<pid>/maps
   And start address of '/lib/x86_64-linux-gnu/libc-2.27.so' retrieved

4) The output was searched manually using ctrl-F, for various pop instructions.

5) Address of execve was found by:
	nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep '\<execve\>'

5.) A python script was generated using the library base and the various ROPgadgets. The string constants ("/sbin/halt", "-p") was written in the buffer itself, and another pointer to this array was written on the input itself.
Then the buffer overflow was caused to go past the return pointer, and then the gadgets were used to manipulate the registers.

To run the attack:
python gen.py | ./victim-nonexec-stack
