# Apply "fuzzy" function signatures from a different Ghidra project.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Rizzo.Apply Signatures


import rizzo

file_path = askFile('Load signature file', 'OK').path

print 'Applying Rizzo signatures, this may take a few minutes...'

rizz = rizzo.Rizzo(currentProgram)
signatures = rizz.load(file_path)
rename_count = rizz.apply(signatures)  # Updated rizzo.apply to return how many functions were renamed
