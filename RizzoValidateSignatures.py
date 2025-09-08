# Validate and inspect multi-stage signature files
#@author fuzzywalls  
#@category TNS
#@menupath TNS.Rizzo.Validate Multi-Stage Signatures

import pickle
import os

# Ask user for the signature file to inspect
file_path = askFile('Select signature file to validate', 'OK').path

print('Validating signature file: {}'.format(file_path))

try:
    with open(file_path, 'rb') as sig_file:
        data = pickle.load(sig_file)
        
    # Detect file type
    if isinstance(data, dict) and 'signatures' in data and 'timestamp' in data:
        # Stage 1 file
        print('\n=== STAGE 1 FILE DETECTED ===')
        signatures = data['signatures']
        print('Program: {}'.format(data.get('program_name', 'Unknown')))
        print('Timestamp: {}'.format(data.get('timestamp', 'Unknown')))
        print('Functions: {}'.format(len(signatures.functions)))
        print('Formal signatures: {}'.format(len(signatures.formal)))
        print('Fuzzy signatures: {}'.format(len(signatures.fuzzy)))
        print('String signatures: {}'.format(len(signatures.strings)))
        print('Immediate signatures: {}'.format(len(signatures.immediates)))
        
        print('\nSample functions:')
        count = 0
        for address, (name, blocks) in signatures.functions.items():
            if count >= 5:
                break
            print('  0x{:x}: {} ({} blocks)'.format(address, name, len(blocks)))
            count += 1
        
        if len(signatures.functions) > 5:
            print('  ... and {} more functions'.format(len(signatures.functions) - 5))
            
    elif hasattr(data, 'formal') and hasattr(data, 'functions'):
        # Standard or enhanced signature file
        print('\n=== SIGNATURE FILE DETECTED ===')
        print('Functions: {}'.format(len(data.functions)))
        print('Formal signatures: {}'.format(len(data.formal)))
        print('Fuzzy signatures: {}'.format(len(data.fuzzy)))
        print('String signatures: {}'.format(len(data.strings)))
        print('Immediate signatures: {}'.format(len(data.immediates)))
        
        # Check for duplicates
        if hasattr(data, 'formaldups'):
            print('Formal duplicates: {}'.format(len(data.formaldups)))
        if hasattr(data, 'fuzzydups'):
            print('Fuzzy duplicates: {}'.format(len(data.fuzzydups)))
        if hasattr(data, 'stringdups'):
            print('String duplicates: {}'.format(len(data.stringdups)))
        
        print('\nSample functions:')
        count = 0
        for address, (name, blocks) in data.functions.items():
            if count >= 5:
                break
            print('  0x{:x}: {} ({} blocks)'.format(address, name, len(blocks)))
            count += 1
            
        if len(data.functions) > 5:
            print('  ... and {} more functions'.format(len(data.functions) - 5))
            
        # Try to detect if this is a multi-stage enhanced file
        has_enhanced_names = False
        has_enhanced_info = hasattr(data, 'enhanced_functions')
        enhanced_info_count = len(getattr(data, 'enhanced_functions', {}))
        fun_name_count = 0
        
        for address, (name, blocks) in data.functions.items():
            if not name.startswith('FUN_'):
                has_enhanced_names = True
            else:
                fun_name_count += 1
        
        if has_enhanced_names or has_enhanced_info:
            print('\n*** ENHANCED SIGNATURES DETECTED ***')
            print('This appears to be from a multi-stage analysis')
            print('Functions with original names (FUN_*): {}'.format(fun_name_count))
            print('Functions with enhanced names: {}'.format(len(data.functions) - fun_name_count))
            
            if has_enhanced_info:
                print('Enhanced function information available: {}'.format(enhanced_info_count))
                print('Enhanced information includes:')
                
                # Sample the first enhanced function to see what info is available
                if enhanced_info_count > 0:
                    sample_addr = next(iter(data.enhanced_functions.keys()))
                    sample_info = data.enhanced_functions[sample_addr]
                    
                    if sample_info.get('signature'):
                        sig_info = sample_info['signature']
                        param_count = len(sig_info.get('parameters', []))
                        return_type = sig_info.get('return_type', {}).get('name', 'unknown')
                        print('  - Function signatures (return: {}, {} parameters)'.format(return_type, param_count))
                    
                    if sample_info.get('variables'):
                        var_count = len(sample_info['variables'])
                        print('  - Local variables ({} variables in sample)'.format(var_count))
                    
                    if sample_info.get('comments'):
                        comment_types = [k for k, v in sample_info['comments'].items() if v]
                        print('  - Comments ({} types: {})'.format(len(comment_types), ', '.join(comment_types)))
        else:
            print('\nThis appears to be a standard signature file')
            
    else:
        print('\n=== UNKNOWN FILE FORMAT ===')
        print('File structure:')
        if isinstance(data, dict):
            for key in data.keys():
                print('  Key: {}'.format(key))
        else:
            print('  Type: {}'.format(type(data)))
            if hasattr(data, '__dict__'):
                for attr in dir(data):
                    if not attr.startswith('_'):
                        print('  Attribute: {}'.format(attr))
        
except Exception as e:
    print('Error loading signature file: {}'.format(str(e)))
    print('This may not be a valid Rizzo signature file')

print('\n=== VALIDATION COMPLETE ===')

# Provide recommendations
print('\nRecommendations:')
if file_path.endswith('.stage1'):
    print('- This is a Stage 1 file')
    print('- Perform manual analysis in Ghidra')
    print('- Run RizzoStage2Update.py to create final signatures')
elif file_path.endswith('.riz'):
    print('- This is a final signature file')
    print('- Use with RizzoApply.py or RizzoApplyEnhanced.py')
    print('- Can be applied to other firmware images')
else:
    print('- Consider using standard file extensions (.stage1 or .riz)')
    print('- Verify file was created with correct Rizzo script')
