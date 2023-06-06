# Create "fuzzy" function signatures that can be shared an applied amongst different Ghidra projects. Based on Rizzo
#@author austinc3030
#@category Rizzo
#@menupath Rizzo.Save Signatures


import rizzo
import os

signature_libary_file = askFile('Signature Library File', 'OK').path
if not signature_libary_file.endswith('.riz'):
    signature_libary_file += '.riz'

passed_index = askInt('Index', 'OK')

print('Building Rizzo signatures from current program, this may take a few minutes...')

rizz = rizzo.Rizzo(currentProgram)

if passed_index > 0:
    print('Adding Rizzo signatures from Existing Signature File, this may take a few minutes...')
    rizz.load_signature_library(signature_libary_file)
    rizz.add_current_program_to_library()
    os.remove(signature_libary_file)
    print('Saving signatures to {new}...'.format(new=signature_libary_file))
    rizz.save_signature_library(signature_libary_file)
else:
    print('Saving signatures to {new}...'.format(new=signature_libary_file))
    rizz.save(signature_libary_file)
