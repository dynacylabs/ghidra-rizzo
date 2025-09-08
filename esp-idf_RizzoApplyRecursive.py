#@runtime PyGhidra
# Apply "fuzzy" function signatures from a different Ghidra project.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Rizzo.Apply Signatures
import os
import glob

import rizzo

release_list = ['release_v2.0',
                'release_v2.1',
                'release_v3.0',
                'release_v3.1',
                'release_v3.2',
                'release_v3.3',
                'release_v4.0',
                'release_v4.1',
                'release_v4.3',
                'release_v4.4',
                'release_v5.0',
                'release_v5.1']

# Remove primary release from release_list
directory_of_rizzo_files = str(askDirectory("Directory",
                                            "Choose esp-idf_rizzo repo Directory:"))
primary_release = str(askString("Primary Release",
                                "Enter the primary release to use (i.e. 'release_v2.0'):"))
release_list.remove(primary_release)

print("Loading Current Program Signatures...")
rizz = rizzo.Rizzo(currentProgram)

primary_release_dir_to_glob = os.path.join(directory_of_rizzo_files, primary_release)
primary_release_dir_glob_str = primary_release_dir_to_glob + "/*.riz"
primary_release_glob = glob.glob(primary_release_dir_glob_str)

total_primary_rename_count = 0
total_rename_count = 0

for rizzo_file in primary_release_glob:
    print("Loading signatures from: {rizzo_file}".format(rizzo_file=rizzo_file))
    signatures = rizz.load(rizzo_file)
    rename_count = rizz.apply(signatures)
    total_primary_rename_count += rename_count
    total_rename_count += rename_count
    del(signatures)

for release in release_list:
    print("Loading signatures from {}".format(release))
    release_dir_to_glob = os.path.join(directory_of_rizzo_files, release)
    release_dir_glob_str = release_dir_to_glob + "/*.riz"
    release_glob = glob.glob(release_dir_glob_str)

    for rizzo_file in release_glob:
        print("Loading signatures from: {rizzo_file}".format(rizzo_file=rizzo_file))
        signatures = rizz.load(rizzo_file)
        rename_count = rizz.apply(signatures)
        total_rename_count += rename_count
        del(signatures)

print("Renamed a total of {total_primary_rename_count} functions from {primary_release}"
      .format(total_primary_rename_count=total_primary_rename_count,
              primary_release=primary_release))
print("Renamed a total of {total_rename_count} functions from all releases."
      .format(total_rename_count=total_rename_count))