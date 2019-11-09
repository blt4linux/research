import re
import os
import sys

if not idc.AskYN(1,("HIDECANCEL\nWARNING: If the import fails, it may break many of your type definitions.\n"
			"It's strongly advised you only run this on databases you're not concerned about wiping.\n"
			"Are you sure you want to continue")):
	sys.exit("User aborted import")

base = os.path.dirname(os.path.abspath(__file__))
fprefix = base + "/"

print("Using file prefix " + fprefix)

defs_path = fprefix + "defs"

print("Starting import!")

# Find all the type definitions available
stored_definitions = dict()
for fname in os.listdir(defs_path):
	parts = os.path.splitext(fname)
	if parts[1] != ".def":
		continue

	name = parts[0]
	filename = defs_path + "/" + fname

	with open(filename, 'rb') as def_file:
		stored_definitions[name] = def_file.read()

# Make a dictionary to find an item's ID by it's name, as this isn't exposed by IDAPython
name_ids = dict()
for i in xrange(1, GetMaxLocalType()):
	name = GetLocalTypeName(i)
	name_ids[name] = i

# The function to replace/insert a type
def ReplaceType(name, struct):
	# First find the name of the 
	# Since IDAPython (at least in 6.8) doesn't support PT_REPLACE, call it in IDC

	# The ID we're going to use insert the type at
	target_id = None

	# See if the type exists in the IDA database already.
	# If so, delete it as IDA sometimes has trouble replacing types
	# however it has no trouble overwriting a deleted type.
	if name in name_ids:
		target_id = name_ids[name]
		SetLocalType(target_id, None, 0)
	else:
		# Otherwise, use -1 which automatically assigns a new ID if necessary
		target_id = -1

	# Make sure the name we've been supplied matches that of the struct's name when parsed
	# This also serves to ensure the struct parses successfully
	# Note we can only do this AFTER deleting the type if it already exists, otherwise we
	# can get errors.
	parsed_name = ParseType(struct, 0x200)[0]
	assert name == parsed_name

	# Prepare the IDC command to create the type
	escaped = struct.encode("string_escape")
	command = "SetLocalType(%d, \"%s\", PT_REPLACE);" % (target_id, escaped)

	# Run it
	new_id = idc.Eval(command)
        if type(new_id) is str:
            print("Import error: " + new_id)
        #print(str(new_id)[1:10])
	print("Inserted type %s to index %d" % (name, new_id))
	return new_id

def PySetType(name, struct):
	# The ID we're going to use insert the type at
	target_id = None

	# See if the type exists in the IDA database already.
	# If so, delete it as IDA sometimes has trouble replacing types
	# however it has no trouble overwriting a deleted type.
	if name in name_ids:
		target_id = name_ids[name]
		SetLocalType(target_id, None, 0)
	else:
		# Otherwise, use -1 which automatically assigns a new ID if necessary
		target_id = -1

	# Make sure the name we've been supplied matches that of the struct's name when parsed
	# This also serves to ensure the struct parses successfully
	# Note we can only do this AFTER deleting the type if it already exists, otherwise we
	# can get errors.
	parsed_name = ParseType(struct, 0x200)[0]
	assert name == parsed_name

	# Run it
	new_id = SetLocalType(target_id, struct, 0)
        if type(new_id) is str:
            print("Py Import error: " + new_id)
        #print(str(new_id)[1:10])
	print("Py Inserted type %s to index %d" % (name, new_id))
	return new_id

# Testing
#ReplaceType("mytestingthing", "struct mytestingthing {\nchar *ptr1; struct nonexistant_struct *ptr2; };\n")
#ReplaceType("mytestingthingi", "typedef int mytestingthingi;\n")

# First, insert any types not already in the database as a typedef to void*. The purpose of this is that otherwise,
# IDA will complain if we use them before we get around to inserting them.
for name in stored_definitions:
	# # Skip anything already in the DB
	# if name in name_ids:
        #   continue

	# Predefine it
	print("Predefining %s" % name)
	new_id = ReplaceType(name, "typedef void* %s" % name)

	# Ensure we insert over it
	name_ids[name] = new_id

# Actually insert everything
for name in stored_definitions:
	contents = stored_definitions[name]
	print("Importing %s" % name)
	PySetType(name, contents)

print("Done!")
