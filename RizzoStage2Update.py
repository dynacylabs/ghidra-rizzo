# Stage 2: Update function definitions while preserving original signatures
#@author fuzzywalls
#@category TNS
#@menupath TNS.Rizzo.Stage 2 - Update with Manual Analysis

import rizzo
import pickle
import os
from ghidra.program.model.symbol import SourceType

# Ask user for the stage 1 file to load
stage1_file = askFile('Load Stage 1 signature file', 'OK').path

# Ask user for the final output file
output_file = askFile('Save final signature file as', 'OK').path
if not output_file.endswith('.riz'):
    output_file += '.riz'

print('Loading Stage 1 data from {}...'.format(stage1_file))

# Load Stage 1 data
try:
    with open(stage1_file, 'rb') as f:
        stage1_data = pickle.load(f)
except Exception as e:
    print('Error loading Stage 1 file: {}'.format(str(e)))
    exit(1)

original_signatures = stage1_data['signatures']
has_enhanced_info = stage1_data.get('has_enhanced_info', False)

print('Loaded {} original function signatures from Stage 1'.format(len(original_signatures.functions)))
if has_enhanced_info:
    print('Stage 1 file contains enhanced function information')

# Create a new Rizzo instance to get current function state
print('Analyzing current program state after manual analysis...')
current_rizz = rizzo.Rizzo(currentProgram)

# Generate current enhanced signatures to capture manual analysis improvements
current_enhanced = current_rizz._generate_enhanced()

# Create the final signature data structure
# We want to keep the ORIGINAL signatures but use the UPDATED function definitions
final_signatures = rizzo.RizzoSignature()

# Copy over the original signature mappings (these are what we match against)
final_signatures.formal = dict(original_signatures.formal)
final_signatures.fuzzy = dict(original_signatures.fuzzy)
final_signatures.strings = dict(original_signatures.strings)
final_signatures.functions = {}  # This will be updated with current definitions
final_signatures.immediates = dict(original_signatures.immediates)

# Copy duplicate sets
final_signatures.formaldups = set(original_signatures.formaldups)
final_signatures.fuzzydups = set(original_signatures.fuzzydups)
final_signatures.stringdups = set(original_signatures.stringdups)
final_signatures.functiondups = set(original_signatures.functiondups) if hasattr(original_signatures, 'functiondups') else set()
final_signatures.immediatedups = set(original_signatures.immediatedups)

# Initialize enhanced functions dictionary
final_signatures.enhanced_functions = {}

# Update function definitions with current state (after manual analysis)
updated_count = 0
not_found_count = 0
enhanced_count = 0

for address, (original_name, original_blocks) in original_signatures.functions.items():
    # Convert integer address back to Ghidra address
    addr_hex = hex(address)
    if addr_hex.endswith('L'):
        addr_hex = addr_hex[:-1]
    
    try:
        curr_addr = current_rizz._address_factory.getAddress(addr_hex)
        function = current_rizz._flat_api.getFunctionAt(curr_addr)
        
        if function:
            # Get the updated function definition
            current_name = function.getName()
            current_blocks = current_rizz._hash_function(function)
            
            # Store the updated function definition
            final_signatures.functions[address] = (current_name, current_blocks)
            
            # Store enhanced information from current state
            if hasattr(current_enhanced, 'enhanced_functions') and address in current_enhanced.enhanced_functions:
                final_signatures.enhanced_functions[address] = current_enhanced.enhanced_functions[address]
                enhanced_count += 1
            
            if current_name != original_name:
                print('Function at {} updated: {} -> {}'.format(addr_hex, original_name, current_name))
            
            updated_count += 1
        else:
            # Function not found, keep original definition
            final_signatures.functions[address] = (original_name, original_blocks)
            not_found_count += 1
            print('Warning: Function not found at {}, keeping original definition'.format(addr_hex))
    
    except Exception as e:
        # Error processing this function, keep original
        final_signatures.functions[address] = (original_name, original_blocks)
        not_found_count += 1
        print('Warning: Error processing function at {}: {}'.format(addr_hex, str(e)))

print('Stage 2 processing complete:')
print('  - {} functions updated with current definitions'.format(updated_count))
print('  - {} functions kept original definitions'.format(not_found_count))
print('  - {} functions have enhanced information (signatures, variables, comments)'.format(enhanced_count))

# Save the final signatures
print('Saving final signatures to {}...'.format(output_file))
with open(output_file, 'wb') as rizz_file:
    pickle.dump(final_signatures, rizz_file)

print('Stage 2 complete!')
print('The signature file now contains:')
print('  - Original signatures (for matching against unanalyzed code)')
print('  - Updated function definitions (from your manual analysis)')
if enhanced_count > 0:
    print('  - Enhanced function information:')
    print('    * Function signatures (return types, parameter types and names)')
    print('    * Local variables (names and data types)')
    print('    * Function comments (all types)')
print('')
print('Use this file with RizzoApplyEnhanced.py to apply to other firmware images.')
print('The enhanced information will restore your manual analysis work automatically.')
