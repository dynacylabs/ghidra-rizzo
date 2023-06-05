# Create "fuzzy" function signatures that can be shared an applied amongst different Ghidra projects.
#@author fuzzywalls
#@category TNS
#@menupath TNS.Rizzo.Save Signatures


import rizzo
import os

signature_file = askFile('Signature File', 'OK').path
if not signature_file.endswith('.riz'):
    signature_file += '.riz'

passed_index = askInt('Index', 'OK')

print('Building Rizzo signatures from current program, this may take a few minutes...')

rizz = rizzo.Rizzo(currentProgram)

if passed_index > 0:
    print('Adding Rizzo signatures from Existing Signature File, this may take a few minutes...')
    rizz.append_signature_file(signature_file)
    
print('Saving signatures to {new}...'.format(new=signature_file))
os.remove(signature_file)
rizz.save(signature_file)
