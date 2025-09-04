# Apply enhanced "fuzzy" function signatures from two-stage analysis
#@author fuzzywalls
#@category TNS
#@menupath TNS.Rizzo.Apply Enhanced Signatures

import rizzo

file_path = askFile('Load signature file (from Stage 2)', 'OK').path

print('Applying enhanced Rizzo signatures, this may take a few minutes...')

rizz = rizzo.Rizzo(currentProgram)
signatures = rizz.load(file_path)

# Check if this is an enhanced signature file
has_enhanced = hasattr(signatures, 'enhanced_functions')
enhanced_function_count = len(getattr(signatures, 'enhanced_functions', {}))

if has_enhanced and enhanced_function_count > 0:
    print('Detected enhanced signature file with {} functions having detailed information'.format(enhanced_function_count))
    print('Enhanced information includes:')
    print('  - Function signatures (return types, parameter types and names)')
    print('  - Local variables (names and data types)')  
    print('  - Function comments (all types)')
    print('')
    
    # Apply basic signatures first
    print('Applying function name signatures...')
    rename_count = rizz.apply(signatures)
    
    # Apply enhanced information
    print('Applying enhanced function information...')
    enhanced_count = 0
    signature_matches = rizz._find_match(signatures)
    
    for matches in signature_matches:
        for curr_func, new_func in matches.iteritems():
            addr_hex = hex(curr_func.address)
            if addr_hex.endswith('L'):
                addr_hex = addr_hex[:-1]
            curr_addr = rizz._address_factory.getAddress(addr_hex)
            
            function = rizz._flat_api.getFunctionAt(curr_addr)
            if function and curr_func.address in signatures.enhanced_functions:
                enhanced_info = signatures.enhanced_functions[curr_func.address]
                enhancements_applied = rizz._apply_enhanced_function_info(function, enhanced_info)
                if enhancements_applied > 0:
                    enhanced_count += 1
                    print('Applied {} enhancements to {}'.format(enhancements_applied, function.getName()))
    
    print('Enhanced signature application complete!')
    print('Applied {} function renames and {} enhanced function definitions'.format(rename_count, enhanced_count))
    
elif hasattr(signatures, 'formal') and hasattr(signatures, 'functions'):
    print('Detected standard two-stage signature file with {} functions'.format(len(signatures.functions)))
    rename_count = rizz.apply(signatures)
    print('Applied {} function renames'.format(rename_count))
    
else:
    print('Standard signature file detected')
    rename_count = rizz.apply(signatures)
    print('Applied {} function renames'.format(rename_count))

print('')
print('Signature application complete!')
print('Your manual analysis has been applied to this firmware image.')
