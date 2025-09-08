# @runtime PyGhidra

# Stage 1: Save enhanced function definitions after manual analysis
# @author fuzzywalls  
# @category TNS
# @menupath TNS.Rizzo.Save Enhanced Signatures (Stage 1)

import pickle
import time
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.pcode import HighFunctionDBUtil

def save_enhanced_signatures():
    """
    Save enhanced function definitions that map to original signatures.
    This should be run AFTER manual analysis to capture the enhanced function definitions.
    """
    
    # Load the original signatures file
    original_file = askFile('Select original signature file (.riz0)', 'OK')
    if not original_file or not original_file.path.endswith('.riz0'):
        print("Please select a valid original signature file (.riz0)")
        return
        
    # Ask for enhanced signatures output file
    enhanced_file_path = askFile('Save enhanced signature file as', 'OK').path
    if not enhanced_file_path.endswith('.riz1'):
        enhanced_file_path += '.riz1'
    
    print('Loading original signatures...')
    
    with open(original_file.path, 'rb') as f:
        original_data = pickle.load(f)
    
    print('Building enhanced signatures (Stage 1), this may take a few minutes...')
    
    # Create enhanced signature data structure
    enhanced_signatures = {
        'rizzo_signatures': original_data['rizzo_signatures'],  # Keep original signatures for matching
        'original_functions': original_data['original_functions'],  # Keep original function info
        'enhanced_functions': {},  # Map address -> enhanced function info
        'timestamp': time.time(),
        'program_name': currentProgram.getName(),
        'original_timestamp': original_data.get('timestamp', 0)
    }
    
    # Set up decompiler for getting enhanced information
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    
    function_manager = currentProgram.getFunctionManager()
    high_func_db_util = HighFunctionDBUtil()
    
    # Test decompiler on first 3 functions to understand what's happening
    print("Testing decompiler on first few functions...")
    test_count = 0
    for test_function in function_manager.getFunctions(True):
        if test_count >= 3:
            break
        test_count += 1
        
        print(f"\nTesting function: {test_function.getName()}")
        test_results = decompiler.decompileFunction(test_function, 60, None)
        
        if not test_results:
            print("  - decompileFunction returned None")
        elif not test_results.decompileCompleted():
            error_msg = test_results.getErrorMessage()
            print(f"  - Decompilation not completed: {error_msg}")
        else:
            print("  - Decompilation completed successfully")
            high_func = test_results.getHighFunction()
            if high_func:
                local_symbols = high_func.getLocalSymbolMap().getSymbols()
                non_param_symbols = [s for s in local_symbols if not s.isParameter()]
                print(f"  - Found {len(non_param_symbols)} local variables")
            else:
                print("  - No high function available")
    
    print("\nStarting full processing...\n")
    
    matched_functions = 0
    new_functions = 0
    variable_extraction_success = 0
    variable_extraction_failed = 0
    
    total_functions = function_manager.getFunctionCount()
    current_function = 0
    
    for function in function_manager.getFunctions(True):
        current_function += 1
        if current_function % 50 == 0:
            print(f"Processing function {current_function}/{total_functions}: {function.getName()}")
            
        address = int(function.getEntryPoint().toString(), 16)
        
        # Check if this function existed in the original signatures
        if address in original_data['original_functions']:
            matched_functions += 1
        else:
            new_functions += 1
        
        # Extract enhanced variables with error tracking
        try:
            enhanced_variables = get_enhanced_function_variables(function, decompiler, high_func_db_util)
            if enhanced_variables:
                variable_extraction_success += 1
            else:
                variable_extraction_failed += 1
        except Exception as e:
            print(f"Failed to extract variables for {function.getName()}: {e}")
            enhanced_variables = []
            variable_extraction_failed += 1
        
        # Store enhanced function information (both matched and new functions)
        enhanced_signatures['enhanced_functions'][address] = {
            'name': function.getName(),
            'signature': get_function_signature_string(function),
            'parameters': get_enhanced_function_parameters(function),
            'return_type': str(function.getReturnType()) if function.getReturnType() else 'void',
            'comment': get_function_comment(function),
            'local_variables': enhanced_variables,
            'decompiled_code': get_decompiled_code(function, decompiler),
            'was_manually_analyzed': address in original_data['original_functions']
        }
    
    decompiler.dispose()
    
    print(f"Saving enhanced signatures to {enhanced_file_path}...")
    
    with open(enhanced_file_path, 'wb') as f:
        pickle.dump(enhanced_signatures, f)
    
    print("Stage 1 complete. Enhanced signatures saved.")
    print(f"Functions from original: {matched_functions}")
    print(f"New functions found: {new_functions}")
    print(f"Total enhanced functions: {len(enhanced_signatures['enhanced_functions'])}")
    print(f"Variable extraction successful: {variable_extraction_success}")
    print(f"Variable extraction failed: {variable_extraction_failed}")

def get_function_signature_string(function):
    """Get a string representation of the function signature."""
    try:
        return function.getSignature().getPrototypeString()
    except:
        return f"{function.getReturnType() or 'void'} {function.getName()}()"

def get_enhanced_function_parameters(function):
    """Extract enhanced function parameter information."""
    params = []
    for param in function.getParameters():
        params.append({
            'name': param.getName(),
            'type': str(param.getDataType()),
            'comment': param.getComment() or "",
            'ordinal': param.getOrdinal()
        })
    return params

def get_function_comment(function):
    """Get function comment."""
    try:
        code_unit = currentProgram.getListing().getCodeUnitAt(function.getEntryPoint())
        if code_unit:
            return code_unit.getComment(code_unit.PLATE_COMMENT) or ""
    except:
        pass
    return ""

def get_enhanced_function_variables(function, decompiler, high_func_db_util):
    """Extract enhanced local variable information using high-level function representation."""
    variables = []
    
    try:
        # Get high-level function representation (using 60 second timeout - compromise between 30 and 120)
        decompiler_results = decompiler.decompileFunction(function, 60, None)
        
        # Detailed debugging to understand what's happening
        if not decompiler_results:
            print(f"Debug: decompileFunction returned None for {function.getName()}")
        elif not decompiler_results.decompileCompleted():
            error_msg = decompiler_results.getErrorMessage()
            print(f"Debug: Decompilation not completed for {function.getName()}: {error_msg}")
        else:
            high_func = decompiler_results.getHighFunction()
            if not high_func:
                print(f"Debug: No high function available for {function.getName()}")
            else:
                local_symbol_map = high_func.getLocalSymbolMap()
                if not local_symbol_map:
                    print(f"Debug: No local symbol map for {function.getName()}")
                else:
                    local_symbols = local_symbol_map.getSymbols()
                    if not local_symbols:
                        print(f"Debug: No local symbols for {function.getName()}")
                    else:
                        non_param_count = 0
                        for symbol in local_symbols:
                            # Skip parameters since they're handled separately
                            if symbol.isParameter():
                                continue
                            non_param_count += 1
                            variables.append({
                                'name': symbol.getName(),
                                'type': str(symbol.getDataType()),
                                'category': 'local',
                                'is_parameter': symbol.isParameter(),
                                'storage': str(symbol.getStorage()) if hasattr(symbol, 'getStorage') else ""
                            })
                        
                        if non_param_count == 0:
                            print(f"Debug: All symbols were parameters for {function.getName()}")
                        else:
                            # Success - return the variables without further warning
                            return variables
                    
        # Only show fallback warning if we actually have an issue
        if not variables:
            print(f"Warning: High-level decompilation failed for {function.getName()}, using basic variable extraction")
            try:
                local_vars = function.getLocalVariables()
                for var in local_vars:
                    variables.append({
                        'name': var.getName(),
                        'type': str(var.getDataType()),
                        'category': 'local',
                        'is_parameter': False,
                        'storage': str(var.getVariableStorage()) if hasattr(var, 'getVariableStorage') else ""
                    })
            except Exception as e:
                print(f"Warning: Could not extract variables for {function.getName()}: {e}")
                
    except Exception as e:
        print(f"Warning: Exception during decompilation for {function.getName()}: {e}")
        
        # Final fallback to basic variable extraction
        try:
            for var in function.getLocalVariables():
                variables.append({
                    'name': var.getName(),
                    'type': str(var.getDataType()),
                    'category': 'local',
                    'is_parameter': False,
                    'storage': ""
                })
        except:
            pass
    
    return variables

def get_decompiled_code(function, decompiler):
    """Get decompiled C code for the function."""
    try:
        decompiler_results = decompiler.decompileFunction(function, 60, None)
        if decompiler_results and decompiler_results.decompileCompleted():
            return decompiler_results.getDecompiledFunction().getC()
    except Exception as e:
        print(f"Could not decompile {function.getName()}: {e}")
    
    return ""

# Run the stage 1 process
save_enhanced_signatures()
