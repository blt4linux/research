import re
import os

print("Starting!")

base = os.path.dirname(os.path.abspath(__file__))
fprefix = base + "/"

print("Using file prefix " + fprefix)

defs_path = fprefix + "defs"

def read_listfile(filename):
	res = []
	with open(fprefix + filename, 'rU') as fileptr:
		for line in fileptr:
			line = line.strip()
			if line:
				res.append(line)
	return res

ignores = read_listfile('ida_ignores.txt')

empty_struct_pattern = re.compile(r"^struct [a-zA-Z0-9_:]+;$")

# Use binary mode to ensure we always use UNIX newlines
definedfile = open(fprefix + 'definedfile.txt', 'wb')
empty_defs_file = open(fprefix + 'empty_defs_file.txt', 'wb')

for i in xrange(1, GetMaxLocalType()):
	name = GetLocalTypeName(i)

	# If this is a deleted type, ignore it
	if not name:
		continue

	code = GetLocalType(i, PRTYPE_TYPE + 0x8)
	empty = empty_struct_pattern.match(code)
	if name in ignores:
		if empty:
			empty_defs_file.write(name)
			empty_defs_file.write('\n')
			print("WARNING: Empty struct %s is in ignore list!" % name)
	else:
		definedfile.write(name)
		definedfile.write('\n')

		filename = defs_path + "/" + name + ".def"

		if empty:
			if os.path.isfile(filename):
				print("WARNING: Definition File for undefined type " + filename)
				print("Please delete this file manually")
		else:
			longdef = GetLocalType(i, PRTYPE_TYPE + PRTYPE_MULTI + 0x8)
			with open(filename, 'wb') as fileptr:
				fileptr.write(longdef)

		#print(name, GetLocalType(i, PRTYPE_TYPE + 0x8))

definedfile.close()
empty_defs_file.close()

print("Done!")
 
