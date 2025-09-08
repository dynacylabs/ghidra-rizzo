# Stage 1: Create function signatures with current definitions for later manual analysis
#@author fuzzywalls
#@category TNS
#@menupath TNS.Rizzo.Stage 1 - Save Initial Signatures

import rizzo
import pickle
import os

# Ask user for the stage 1 output file
file_path = askFile('Save Stage 1 signature file as', 'OK').path
if not file_path.endswith('.stage1'):
    file_path += '.stage1'

print('Building Stage 1 Rizzo signatures with current function definitions...')

# Create Rizzo instance to generate signatures
rizz = rizzo.Rizzo(currentProgram)

# Generate enhanced signatures that include detailed function information
enhanced_signatures = rizz._generate_enhanced()

# Create Stage 1 data structure
stage1_data = {
    'signatures': enhanced_signatures,  # Contains the original signatures with enhanced info
    'timestamp': rizzo.time.time(),
    'program_name': currentProgram.getName(),
    'has_enhanced_info': True
}

print('Saving Stage 1 data to {}...'.format(file_path))
with open(file_path, 'wb') as stage1_file:
    pickle.dump(stage1_data, stage1_file)

function_count = len(enhanced_signatures.functions)
enhanced_count = len(getattr(enhanced_signatures, 'enhanced_functions', {}))

print('Stage 1 complete! Generated {} function signatures with {} enhanced function definitions.'.format(function_count, enhanced_count))
print('Enhanced information captured:')
print('  - Function signatures (return types, parameter types and names)')
print('  - Local variables (names and data types)')
print('  - Function comments (all types)')
print('')
print('You can now perform manual analysis in Ghidra:')
print('  - Rename functions with meaningful names')
print('  - Fix function signatures and parameter types')
print('  - Update variable names and types')
print('  - Add/improve comments')
print('  - Set proper calling conventions')
print('')
print('When ready, run Stage 2 to capture the updated function definitions.')
