# Apply "fuzzy" function signatures from a different Ghidra project.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Rizzo.Apply Signatures


import os
import glob

import rizzo

directory_of_rizzo_files = str(askDirectory("Directory", "Choose directory:"))
directory_to_glob = directory_of_rizzo_files + "/*.riz"
rizzo_files_glob = glob.glob(directory_to_glob)

print("Loading Current Program Signatures...")
rizz = rizzo.Rizzo(currentProgram)

total_rename_count = 0

for rizzo_file in rizzo_files_glob:
    print("Loading signatures from: {}".format(rizzo_file))

    signatures = rizz.load(rizzo_file)
    rizz.apply(signatures)
    del(signatures)

    rename_count = rizz.apply(signatures)
    total_rename_count += rename_count

print("Renamed a total of {total_rename_count} functions.".format(total_rename_count=total_rename_count))
