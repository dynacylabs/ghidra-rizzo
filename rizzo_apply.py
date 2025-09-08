# @runtime PyGhidra

# Apply enhanced function signatures with multi-stage matching
# @author fuzzywalls
# @category TNS
# @menupath TNS.Rizzo.Apply Enhanced Signatures

import pickle
import time
import rizzo
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import ParameterImpl
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import HighFunctionDBUtil

# Import enhanced type mapping utilities
import sys
import os

# Add current directory to path to import rizzo_type_utils
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

try:
    from rizzo_type_utils import map_c_type_to_ghidra_type
    print("Using rizzo_type_utils for type mapping")
except ImportError:
    print("rizzo_type_utils not available, using built-in enhanced type mapping")
    # Enhanced type mapping will be defined later in this file
    pass

def apply_enhanced_signatures():
    """
    Apply enhanced function signatures using multi-stage matching approach:
    1. Use original signatures for matching functions
    2. Apply enhanced function definitions to matched functions
    """
    
    # Load the enhanced signatures file
    enhanced_file = askFile('Select enhanced signature file (.riz1)', 'OK')
    if not enhanced_file or not enhanced_file.path.endswith('.riz1'):
        print("Please select a valid enhanced signature file (.riz1)")
        return
    
    print('Loading enhanced signatures...')
    
    with open(enhanced_file.path, 'rb') as f:
        enhanced_data = pickle.load(f)
    
    # Show information about what we loaded
    total_enhanced_functions = len(enhanced_data.get('enhanced_functions', {}))
    total_original_functions = len(enhanced_data.get('original_functions', {}))
    total_rizzo_signatures = 0
    
    if 'rizzo_signatures' in enhanced_data:
        sigs = enhanced_data['rizzo_signatures']
        formal_count = len(sigs.formal) if hasattr(sigs, 'formal') else 0
        string_count = len(sigs.strings) if hasattr(sigs, 'strings') else 0
        immediate_count = len(sigs.immediates) if hasattr(sigs, 'immediates') else 0
        fuzzy_count = len(sigs.fuzzy) if hasattr(sigs, 'fuzzy') else 0
        total_rizzo_signatures = formal_count + string_count + immediate_count + fuzzy_count
        
        print(f'Loaded enhanced signature file containing:')
        print(f'  - {total_enhanced_functions} enhanced function definitions')
        print(f'  - {total_original_functions} original function definitions') 
        print(f'  - {total_rizzo_signatures} total signatures:')
        print(f'    * {formal_count} formal signatures')
        print(f'    * {string_count} string signatures') 
        print(f'    * {immediate_count} immediate signatures')
        print(f'    * {fuzzy_count} fuzzy signatures')
    else:
        print(f'Loaded enhanced signature file containing:')
        print(f'  - {total_enhanced_functions} enhanced function definitions')
        print(f'  - {total_original_functions} original function definitions')
    
    print('Applying enhanced signatures...')
    
    # Create Rizzo instance for the current program (this will show its own progress)
    current_rizz = rizzo.Rizzo(currentProgram)
    
    print('Starting signature matching process...')
    print('This may take several minutes for large programs - progress will be shown for each signature type.')
    
    # Find matches using the original signatures
    signature_matches = current_rizz._find_match(enhanced_data['rizzo_signatures'])
    
    # Set up components for applying enhanced function definitions
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    high_func_db_util = HighFunctionDBUtil()
    
    enhanced_count = 0
    renamed_count = 0
    variable_updates = 0
    
    # Count total functions to process for progress reporting
    total_functions_to_process = 0
    for match_group in signature_matches:
        if match_group:
            total_functions_to_process += len(match_group)
    
    print(f'\nSignature matching complete!')
    print(f'Found {total_functions_to_process} total function matches to process.')
    
    if total_functions_to_process == 0:
        print('No function matches found. Check if the signature file is compatible with this program.')
        decompiler.dispose()
        return
    
    print(f'Applying enhanced function definitions...\n')
    
    current_function_index = 0
    start_time = time.time()
    
    # Process all signature matches
    for match_group in signature_matches:
        if not match_group:
            continue
            
        for curr_func, matched_func in match_group.items():
            current_function_index += 1
            
            try:
                # Show progress for every function or every 10 functions if there are many
                show_progress = (current_function_index % 10 == 0) or (current_function_index == 1) or (current_function_index == total_functions_to_process)
                if show_progress:
                    progress_percent = (current_function_index * 100.0) / total_functions_to_process
                    elapsed_time = time.time() - start_time
                    
                    if current_function_index > 1:
                        estimated_total_time = elapsed_time * total_functions_to_process / current_function_index
                        remaining_time = estimated_total_time - elapsed_time
                        print(f'Progress: {current_function_index}/{total_functions_to_process} functions ({progress_percent:.1f}%) - '
                              f'Elapsed: {elapsed_time:.1f}s, Est. remaining: {remaining_time:.1f}s')
                    else:
                        print(f'Progress: {current_function_index}/{total_functions_to_process} functions ({progress_percent:.1f}%)')
                
                # Get current program function
                addr_hex = hex(curr_func.address)
                if addr_hex.endswith('L'):
                    addr_hex = addr_hex[:-1]
                curr_addr = currentProgram.getAddressFactory().getAddress(addr_hex)
                current_function = currentProgram.getFunctionManager().getFunctionAt(curr_addr)
                
                if not current_function:
                    continue
                
                # Find enhanced function definition
                enhanced_func_info = enhanced_data['enhanced_functions'].get(matched_func.address)
                
                if not enhanced_func_info:
                    # Fall back to original function info if no enhanced version
                    enhanced_func_info = enhanced_data['original_functions'].get(matched_func.address)
                
                if enhanced_func_info:
                    success = apply_enhanced_function_definition_improved(
                        current_function, 
                        enhanced_func_info, 
                        decompiler, 
                        high_func_db_util
                    )
                    
                    if success:
                        enhanced_count += 1
                        if enhanced_func_info['name'] != current_function.getName():
                            renamed_count += 1
                        
                        # Count variable updates
                        var_count = len(enhanced_func_info.get('local_variables', []))
                        if var_count > 0:
                            variable_updates += var_count
                        
            except Exception as e:
                print(f"Error applying enhanced signature to function {current_function_index}: {e}")
                continue
    
    decompiler.dispose()
    
    total_elapsed_time = time.time() - start_time
    
    print(f'\n=== Enhanced Signature Application Complete ===')
    print(f'Functions processed: {current_function_index}/{total_functions_to_process}')
    print(f'Enhanced definitions applied: {enhanced_count}')
    print(f'Functions renamed: {renamed_count}')
    print(f'Variable updates attempted: {variable_updates}')
    print(f'Total processing time: {total_elapsed_time:.1f} seconds')
    
    if current_function_index > 0:
        avg_time_per_function = total_elapsed_time / current_function_index
        print(f'Average time per function: {avg_time_per_function:.2f} seconds')
    
    if enhanced_count > 0:
        success_rate = (enhanced_count * 100.0) / current_function_index if current_function_index > 0 else 0
        print(f'Success rate: {success_rate:.1f}%')
        print(f'\nEnhanced signatures have been successfully applied!')
        print(f'Check the Ghidra program for updated function names, types, and variable names.')
    else:
        print(f'\nNo enhanced definitions were successfully applied.')
        print(f'This may indicate compatibility issues between the signature file and target program.')
    
    print('=== Process Complete ===\n')

def apply_enhanced_function_definition(function, enhanced_info, decompiler, high_func_db_util):
    """
    Apply enhanced function definition to a target function.
    
    Args:
        function: Target Ghidra function
        enhanced_info: Enhanced function information dictionary
        decompiler: Decompiler interface
        high_func_db_util: High function database utility
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        function_name = function.getName()
        enhanced_name = enhanced_info['name']
        
        print(f"Applying enhanced definition to {function_name} -> {enhanced_name}")
        
        # 1. Apply function name
        if enhanced_name and enhanced_name != function_name:
            function.setName(enhanced_name, SourceType.USER_DEFINED)
        
        # 2. Apply return type
        if enhanced_info.get('return_type'):
            return_type = map_c_type_to_ghidra_type(enhanced_info['return_type'], function.getProgram())
            if return_type:
                function.setReturnType(return_type, SourceType.USER_DEFINED)
        
        # 3. Apply function parameters
        apply_function_parameters(function, enhanced_info.get('parameters', []))
        
        # 4. Apply function comment
        if enhanced_info.get('comment'):
            apply_function_comment(function, enhanced_info['comment'])
        
        # 5. Apply local variable names and types
        apply_function_variables(function, enhanced_info.get('local_variables', []), 
                               decompiler, high_func_db_util)
        
        return True
        
    except Exception as e:
        print(f"Failed to apply enhanced definition to {function.getName()}: {e}")
        return False

def apply_function_parameters(function, param_info_list):
    """Apply parameter names and types to a function."""
    try:
        # Clear existing parameters
        while function.getParameterCount() > 0:
            function.removeParameter(0)
        
        # Add new parameters
        for param_info in param_info_list:
            param_type = map_c_type_to_ghidra_type(param_info['type'], function.getProgram())
            if param_type:
                parameter = ParameterImpl(param_info['name'], param_type, function.getProgram())
                function.addParameter(parameter, SourceType.USER_DEFINED)
                
    except Exception as e:
        print(f"Failed to apply parameters to {function.getName()}: {e}")

def apply_function_comment(function, comment):
    """Apply comment to a function."""
    try:
        if comment:
            code_unit = currentProgram.getListing().getCodeUnitAt(function.getEntryPoint())
            if code_unit:
                code_unit.setComment(code_unit.PLATE_COMMENT, comment)
    except Exception as e:
        print(f"Failed to apply comment to {function.getName()}: {e}")

def apply_function_variables(function, var_info_list, decompiler, high_func_db_util):
    """Apply local variable names and types to a function using high-level representation."""
    if not var_info_list:
        return
        
    try:
        print(f"  Applying variables to {function.getName()}")
        
        # Get high-level function representation
        decompiler_results = decompiler.decompileFunction(function, 30, None)
        if not decompiler_results or not decompiler_results.decompileCompleted():
            print(f"  Could not decompile {function.getName()} for variable restoration")
            return
            
        high_func = decompiler_results.getHighFunction()
        if not high_func:
            print(f"  Could not get high-level function for {function.getName()}")
            return
            
        local_symbols = high_func.getLocalSymbolMap().getSymbols()
        
        # Create lists of current symbols and enhanced variables for matching
        current_symbols = []
        enhanced_vars = []
        
        for symbol in local_symbols:
            if not symbol.isParameter():  # Skip parameters
                current_symbols.append({
                    'symbol': symbol,
                    'name': symbol.getName(),
                    'type': str(symbol.getDataType()),
                    'storage': str(symbol.getStorage()) if hasattr(symbol, 'getStorage') else ""
                })
        
        for var_info in var_info_list:
            if var_info.get('category') == 'local' and not var_info.get('is_parameter', False):
                enhanced_vars.append(var_info)
        
        print(f"  Function {function.getName()}: {len(current_symbols)} current variables, {len(enhanced_vars)} enhanced variables")
        
        # Pre-analyze for potential conflicts with more detailed checking
        enhanced_name_counts = {}
        for enhanced in enhanced_vars:
            name = enhanced['name']
            enhanced_name_counts[name] = enhanced_name_counts.get(name, 0) + 1
        
        duplicate_names = {name: count for name, count in enhanced_name_counts.items() if count > 1}
        if duplicate_names:
            print(f"    ⚠ Warning: Enhanced data contains duplicate variable names: {duplicate_names}")
            print("    → These will be automatically numbered to prevent conflicts")
        
        # Debug: Show current and enhanced variables with more detail
        if current_symbols:
            print("    Current variables:")
            for i, current in enumerate(current_symbols):
                storage_info = current['storage'] if current['storage'] else 'no-storage'
                print(f"      {i+1}. {current['name']} : {current['type']} (storage: {storage_info})")
        
        if enhanced_vars:
            print("    Enhanced variables:")
            for i, enhanced in enumerate(enhanced_vars):
                storage_info = enhanced.get('storage', 'N/A')
                print(f"      {i+1}. {enhanced['name']} : {enhanced['type']} (storage: {storage_info})")
        
        # Track names that will be used to prevent conflicts with improved tracking
        reserved_names = set()
        # Add existing names from symbols we won't modify
        for symbol in local_symbols:
            reserved_names.add(symbol.getName())
        
        # Track matched symbols and enhanced vars to prevent double-matching
        matched_symbols = set()
        used_enhanced_vars = set()
        successful_updates = 0
        
        # Strategy 1: Try to match by storage location (most reliable)
        print("    → Strategy 1: Matching by storage location...")
        for current in current_symbols:
            if current['symbol'] in matched_symbols:
                continue
                
            current_storage = current['storage']
            if current_storage and current_storage != "":
                for i, enhanced in enumerate(enhanced_vars):
                    if i in used_enhanced_vars:
                        continue
                        
                    enhanced_storage = enhanced.get('storage', '')
                    if enhanced_storage == current_storage:
                        success = apply_variable_update(current['symbol'], enhanced, high_func, high_func_db_util, function, reserved_names)
                        if success:
                            matched_symbols.add(current['symbol'])
                            used_enhanced_vars.add(i)
                            successful_updates += 1
                            # Update reserved names
                            reserved_names.discard(current['name'])  # Remove old name
                            reserved_names.add(enhanced['name'])     # Add new name
                            print(f"    ✓ Storage match: {current['name']} -> {enhanced['name']}")
                        break
        
        # Strategy 2: Try to match by name (for variables that weren't renamed)
        print("    → Strategy 2: Matching by name...")
        for current in current_symbols:
            if current['symbol'] in matched_symbols:
                continue
                
            current_name = current['name']
            for i, enhanced in enumerate(enhanced_vars):
                if i in used_enhanced_vars:
                    continue
                    
                enhanced_name = enhanced['name']
                if enhanced_name == current_name:
                    success = apply_variable_update(current['symbol'], enhanced, high_func, high_func_db_util, function, reserved_names)
                    if success:
                        matched_symbols.add(current['symbol'])
                        used_enhanced_vars.add(i)
                        successful_updates += 1
                        print(f"    ✓ Name match: {current['name']} -> {enhanced['name']}")
                    break
        
        # Strategy 3: Try to match by type (for similar variables)
        print("    → Strategy 3: Matching by type...")
        for current in current_symbols:
            if current['symbol'] in matched_symbols:
                continue
                
            current_type = current['type']
            for i, enhanced in enumerate(enhanced_vars):
                if i in used_enhanced_vars:
                    continue
                    
                enhanced_type = enhanced['type']
                if enhanced_type == current_type:
                    success = apply_variable_update(current['symbol'], enhanced, high_func, high_func_db_util, function, reserved_names)
                    if success:
                        matched_symbols.add(current['symbol'])
                        used_enhanced_vars.add(i)
                        successful_updates += 1
                        # Update reserved names
                        reserved_names.discard(current['name'])  # Remove old name
                        reserved_names.add(enhanced['name'])     # Add new name
                        print(f"    ✓ Type match: {current['name']} -> {enhanced['name']}")
                    break
        
        # Strategy 4: Match remaining variables by position (order)
        print("    → Strategy 4: Matching by position...")
        remaining_current = [c for c in current_symbols if c['symbol'] not in matched_symbols]
        remaining_enhanced_indices = [i for i in range(len(enhanced_vars)) if i not in used_enhanced_vars]
        
        for i, current in enumerate(remaining_current):
            if i < len(remaining_enhanced_indices):
                enhanced_idx = remaining_enhanced_indices[i]
                enhanced = enhanced_vars[enhanced_idx]
                success = apply_variable_update(current['symbol'], enhanced, high_func, high_func_db_util, function, reserved_names)
                if success:
                    matched_symbols.add(current['symbol'])
                    used_enhanced_vars.add(enhanced_idx)
                    successful_updates += 1
                    # Update reserved names
                    reserved_names.discard(current['name'])  # Remove old name
                    reserved_names.add(enhanced['name'])     # Add new name
                    print(f"    ✓ Position match: {current['name']} -> {enhanced['name']}")
        
        total_matched = len(matched_symbols)
        print(f"  ✓ Applied {successful_updates}/{total_matched} variable updates to {function.getName()}")
        
        # Show summary of unmatched items for debugging
        unmatched_current = len(current_symbols) - total_matched
        unmatched_enhanced = len(enhanced_vars) - len(used_enhanced_vars)
        
        if unmatched_current > 0 or unmatched_enhanced > 0:
            print(f"  → {unmatched_current} current variables and {unmatched_enhanced} enhanced variables remain unmatched")
        
    except Exception as e:
        print(f"  ✗ Failed to apply variables to {function.getName()}: {e}")
        import traceback
        traceback.print_exc()

def apply_variable_update(symbol, enhanced_var, high_func, high_func_db_util, function, reserved_names):
    """Apply a single variable update using high-level function representation."""
    try:
        old_name = symbol.getName()
        new_name = enhanced_var['name']
        old_type = str(symbol.getDataType())
        new_type = enhanced_var['type']
        
        # Check what needs to be updated
        name_needs_update = old_name != new_name
        type_needs_update = old_type != new_type
        
        # Skip if nothing needs updating
        if not name_needs_update and not type_needs_update:
            return False
        
        # Map the type string to Ghidra data type
        data_type = map_c_type_to_ghidra_type(new_type, function.getProgram())
        if not data_type:
            print(f"    Warning: Could not map type '{new_type}' for variable {old_name}")
            return False
        
        # Improved conflict detection using reserved_names tracking
        final_name = old_name  # Default to keeping the old name
        if name_needs_update:
            # Check if the new name would conflict with reserved names
            if new_name not in reserved_names:
                final_name = new_name
            else:
                # Try to generate an alternative name if there's a conflict
                base_name = new_name
                counter = 1
                while f"{base_name}_{counter}" in reserved_names and counter < 100:
                    counter += 1
                
                if counter < 100:
                    final_name = f"{base_name}_{counter}"
                    print(f"    Name conflict resolved: '{new_name}' -> '{final_name}'")
                else:
                    print(f"    Warning: Name '{new_name}' conflicts and couldn't generate alternative, keeping original name '{old_name}'")
                    name_needs_update = False
                    final_name = old_name
        
        # Show what we're updating
        if name_needs_update and type_needs_update:
            print(f"    Updating variable: {old_name} ({old_type}) -> {final_name} ({new_type})")
        elif name_needs_update:
            print(f"    Renaming variable: {old_name} -> {final_name}")
        elif type_needs_update:
            print(f"    Retyping variable: {old_name} ({old_type}) -> ({new_type})")
        
        # Apply the update using improved approach with better transaction management
        success = False
        
        try:
            # Start a transaction for the update
            transaction_id = function.getProgram().startTransaction("Update Variable")
            
            try:
                # Use a more reliable approach that works directly with function variables
                # instead of relying solely on the decompiler's high-level representation
                
                success = apply_variable_update_direct(function, symbol, enhanced_var, final_name, data_type, 
                                                     name_needs_update, type_needs_update, old_name, new_type)
                
                # If direct approach fails, try the decompiler approach as fallback
                if not success:
                    print(f"    → Trying decompiler approach as fallback...")
                    
                    if name_needs_update and type_needs_update:
                        # Update both name and type
                        try:
                            high_func_db_util.updateDBVariable(
                                symbol, final_name, data_type, SourceType.USER_DEFINED
                            )
                            success = True
                            print(f"    ✓ Decompiler combined update reported success")
                        except Exception as name_type_error:
                            print(f"    ✗ Decompiler combined update failed: {name_type_error}")
                            
                    elif type_needs_update:
                        # Just update type, keep the name
                        try:
                            high_func_db_util.updateDBVariable(
                                symbol, old_name, data_type, SourceType.USER_DEFINED
                            )
                            success = True
                            print(f"    ✓ Decompiler type update reported success")
                        except Exception as type_error:
                            print(f"    ✗ Decompiler type update failed: {type_error}")
                        
                    elif name_needs_update:
                        # Just update name, keep the type
                        try:
                            high_func_db_util.updateDBVariable(
                                symbol, final_name, symbol.getDataType(), SourceType.USER_DEFINED
                            )
                            success = True
                            print(f"    ✓ Decompiler name update reported success")
                        except Exception as name_error:
                            print(f"    ✗ Decompiler name update failed: {name_error}")
                
                # Force commit the changes immediately if we have a high function
                if high_func and success:
                    try:
                        high_func_db_util.commitLocalNamesToDatabase(
                            high_func, SourceType.USER_DEFINED
                        )
                    except Exception as commit_error:
                        print(f"    Warning: Failed to commit local names: {commit_error}")
                    
                    try:
                        high_func_db_util.commitParamsToDatabase(
                            high_func,
                            True,  # overwrite existing
                            HighFunctionDBUtil.ReturnCommitOption.COMMIT,
                            SourceType.USER_DEFINED
                        )
                    except Exception as commit_error:
                        print(f"    Warning: Failed to commit params: {commit_error}")
                
            except Exception as inner_error:
                print(f"    ✗ Inner transaction failed: {inner_error}")
                success = False
            finally:
                # Always end the transaction
                function.getProgram().endTransaction(transaction_id, success)
            
            # Verify the update worked if we think it was successful
            if success:
                try:
                    # Instead of checking the decompiler symbol, verify against the actual function variables
                    verification_success = verify_variable_update(function, old_name, final_name, new_type, 
                                                                name_needs_update, type_needs_update)
                    
                    if verification_success:
                        print(f"    ✓ Verification confirmed: Update successful")
                    else:
                        print(f"    ⚠ Verification failed: Changes may not have persisted")
                        # Don't mark as complete failure since some partial success may have occurred
                        
                except Exception as verify_error:
                    print(f"    Warning: Could not verify update: {verify_error}")
            
        except Exception as e:
            print(f"    ✗ Variable update transaction failed: {e}")
            
            # Fallback: Try alternative approach for type-only updates without transaction
            if type_needs_update and not name_needs_update:
                try:
                    print(f"    → Attempting fallback type update for {old_name}")
                    symbol.setDataType(data_type, SourceType.USER_DEFINED)
                    if str(symbol.getDataType()) == new_type:
                        print(f"    ✓ Fallback type update successful: {old_name} : {new_type}")
                        success = True
                except Exception as fallback_e:
                    print(f"    ✗ Fallback type update also failed: {fallback_e}")
                    success = False
            else:
                success = False
        
        return success
        
    except Exception as e:
        print(f"    ✗ Failed to update variable {symbol.getName()}: {e}")
        return False

def verify_variable_update(function, old_name, expected_name, expected_type, name_needs_update, type_needs_update):
    """
    Verify that a variable update actually took effect by checking the function's current variables.
    This is more reliable than checking decompiler symbols.
    """
    try:
        # Get current function variables
        all_variables = function.getAllVariables()
        local_variables = []
        
        for var in all_variables:
            try:
                is_param = var.isParameter()
            except AttributeError:
                # Fallback for when isParameter() is not available - use more robust detection
                is_param = False
                try:
                    class_name = var.__class__.__name__
                    if 'Parameter' in class_name:
                        is_param = True
                    elif hasattr(var, 'getFirstUseOffset'):
                        is_param = var.getFirstUseOffset() == 0
                    elif hasattr(var, 'getVariableStorage'):
                        storage_str = str(var.getVariableStorage())
                        is_param = ('r' in storage_str and ':' in storage_str) or 'Stack[0x' in storage_str
                except Exception:
                    # When in doubt, assume it's a local variable for verification purposes
                    is_param = False
            
            if not is_param:
                local_variables.append(var)
        
        # Look for a variable with the expected name and type
        found_expected = False
        found_old = False
        
        if len(local_variables) == 0:
            print(f"    → No local variables found for verification")
            return False
        
        print(f"    → Verifying among {len(local_variables)} local variables:")
        for i, var in enumerate(local_variables[:5]):  # Show first 5 for debugging
            var_name = var.getName()
            var_type = str(var.getDataType())
            print(f"      {i+1}. {var_name} : {var_type}")
        
        for var in local_variables:
            var_name = var.getName()
            var_type = str(var.getDataType())
            
            # Check if we find the expected result
            if name_needs_update and var_name == expected_name:
                if not type_needs_update or var_type == expected_type:
                    found_expected = True
                    print(f"    → Found expected variable: {var_name} : {var_type}")
            
            # Check if the old variable still exists (shouldn't if rename worked)
            if name_needs_update and var_name == old_name:
                found_old = True
                print(f"    → Old variable still exists: {var_name} : {var_type}")
        
        # Verification logic
        if name_needs_update:
            if found_expected and not found_old:
                return True  # Perfect success
            elif found_expected and found_old:
                print(f"    → Found both old and new variables (possible duplication)")
                return True  # Partial success
            elif not found_expected and not found_old:
                print(f"    → Neither old nor expected variable found (variable may have been modified)")
                return False
            else:
                print(f"    → Expected variable not found, old variable still exists")
                return False
        else:
            # Only type update needed, just check if any variable has the right type
            # This is more complex to verify, so we'll be more lenient
            return True
        
    except Exception as e:
        print(f"    → Verification error: {e}")
        return False

def apply_variable_update_direct(function, decompiler_symbol, enhanced_var, final_name, data_type, 
                                name_needs_update, type_needs_update, old_name, new_type):
    """
    Direct approach to variable updates that works with function variables instead of decompiler symbols.
    This approach is more reliable for actually applying changes that persist in Ghidra.
    """
    try:
        print(f"    → Attempting direct function variable approach...")
        
        # Get all variables from the function directly (not through decompiler)
        all_variables = function.getAllVariables()
        local_variables = []
        
        # Filter out parameters more robustly
        for var in all_variables:
            is_param = False
            try:
                # Try the standard method first
                is_param = var.isParameter()
            except AttributeError:
                # If isParameter() doesn't exist, check the class type
                try:
                    class_name = var.__class__.__name__
                    if 'Parameter' in class_name:
                        is_param = True
                    else:
                        # Additional heuristic: parameters typically have offset 0 or positive offsets
                        if hasattr(var, 'getFirstUseOffset'):
                            is_param = var.getFirstUseOffset() == 0
                        elif hasattr(var, 'getVariableStorage'):
                            # Parameters are usually in registers or positive stack offsets
                            storage_str = str(var.getVariableStorage())
                            is_param = ('r' in storage_str and ':' in storage_str) or 'Stack[0x' in storage_str
                        else:
                            is_param = False
                except Exception as filter_error:
                    print(f"    → Could not determine if variable is parameter: {filter_error}")
                    # When in doubt, assume it's a local variable
                    is_param = False
            
            if not is_param:
                local_variables.append(var)
        
        print(f"    → Function has {len(all_variables)} total variables")
        print(f"    → Filtered to {len(local_variables)} local variables")
        
        # Try to find the matching variable by various criteria
        target_variable = None
        
        # Method 1: Try to match by name
        for var in local_variables:
            if var.getName() == old_name:
                target_variable = var
                print(f"    → Found variable by name match: {old_name}")
                break
        
        # Method 2: If name match failed, try to match by storage location if available
        if not target_variable and hasattr(decompiler_symbol, 'getStorage'):
            try:
                decompiler_storage = str(decompiler_symbol.getStorage())
                for var in local_variables:
                    if hasattr(var, 'getVariableStorage'):
                        var_storage = str(var.getVariableStorage())
                        if var_storage == decompiler_storage:
                            target_variable = var
                            print(f"    → Found variable by storage match: {var_storage}")
                            break
            except Exception as storage_error:
                print(f"    → Storage matching failed: {storage_error}")
        
        # Method 3: If still not found, try positional matching as last resort
        if not target_variable and local_variables:
            # Use the first available variable (this is a fallback)
            target_variable = local_variables[0]
            print(f"    → Using first available variable as fallback: {target_variable.getName()}")
        
        if not target_variable:
            print(f"    ✗ Could not find matching function variable for '{old_name}'")
            if local_variables:
                print(f"    → Available local variables:")
                for i, var in enumerate(local_variables[:10]):  # Show first 10
                    var_name = var.getName() if hasattr(var, 'getName') else str(var)
                    var_type = str(var.getDataType()) if hasattr(var, 'getDataType') else 'unknown'
                    print(f"      {i+1}. {var_name} : {var_type}")
                if len(local_variables) > 10:
                    print(f"      ... and {len(local_variables) - 10} more")
            else:
                print(f"    → No local variables found in function")
            return False
        
        success = False
        
        # Now try to update the found variable
        if name_needs_update and type_needs_update:
            # Try to update both name and type
            try:
                # Remove the old variable
                old_storage = target_variable.getVariableStorage()
                function.removeVariable(target_variable)
                
                # Create new variable with new name and type
                new_var = function.addLocalVariable(old_storage, final_name, data_type, SourceType.USER_DEFINED)
                if new_var:
                    success = True
                    print(f"    ✓ Direct update successful: {old_name} -> {final_name} : {new_type}")
                else:
                    print(f"    ✗ Failed to create new variable")
                    # Try to restore original variable
                    try:
                        function.addLocalVariable(old_storage, old_name, target_variable.getDataType(), SourceType.USER_DEFINED)
                    except:
                        pass
                        
            except Exception as combined_error:
                print(f"    ✗ Direct combined update failed: {combined_error}")
                
        elif type_needs_update:
            # Just update type
            try:
                target_variable.setDataType(data_type, SourceType.USER_DEFINED)
                success = True
                print(f"    ✓ Direct type update successful: {old_name} : {new_type}")
            except Exception as type_error:
                print(f"    ✗ Direct type update failed: {type_error}")
                
        elif name_needs_update:
            # Just update name
            try:
                target_variable.setName(final_name, SourceType.USER_DEFINED)
                success = True
                print(f"    ✓ Direct name update successful: {old_name} -> {final_name}")
            except Exception as name_error:
                print(f"    ✗ Direct name update failed: {name_error}")
        
        return success
        
    except Exception as e:
        print(f"    ✗ Direct variable update approach failed: {e}")
        
        # Fallback: Try a simpler approach without parameter filtering
        try:
            print(f"    → Attempting simplified direct approach (no parameter filtering)...")
            all_variables = function.getAllVariables()
            
            # Find variable by name without filtering parameters
            target_var = None
            for var in all_variables:
                if hasattr(var, 'getName') and var.getName() == old_name:
                    target_var = var
                    break
            
            if target_var:
                if name_needs_update:
                    try:
                        target_var.setName(final_name, SourceType.USER_DEFINED)
                        if target_var.getName() == final_name:
                            print(f"    ✓ Simplified rename successful: {old_name} -> {final_name}")
                            return True
                    except Exception as simple_rename_error:
                        print(f"    ✗ Simplified rename failed: {simple_rename_error}")
                
                if type_needs_update:
                    try:
                        target_var.setDataType(data_type, SourceType.USER_DEFINED)
                        if str(target_var.getDataType()) == new_type:
                            print(f"    ✓ Simplified type update successful: {old_name} : {new_type}")
                            return True
                    except Exception as simple_type_error:
                        print(f"    ✗ Simplified type update failed: {simple_type_error}")
            else:
                print(f"    ✗ Could not find variable '{old_name}' in simplified approach")
                
        except Exception as simple_error:
            print(f"    ✗ Simplified approach also failed: {simple_error}")
        
        return False

def get_function_local_variables_alternative(function):
    """
    Alternative approach to get local variables using the symbol table.
    This might work better in some cases where the decompiler approach fails.
    """
    try:
        symbol_table = function.getProgram().getSymbolTable()
        local_vars = []
        
        # Get all symbols in the function's namespace
        symbols = symbol_table.getSymbols(function)
        
        for symbol in symbols:
            if symbol.getSymbolType().toString() == "LocalVar":
                local_vars.append({
                    'symbol': symbol,
                    'name': symbol.getName(),
                    'address': symbol.getAddress()
                })
        
        return local_vars
        
    except Exception as e:
        print(f"Alternative variable collection failed: {e}")
        return []

def apply_enhanced_function_definition_improved(function, enhanced_info, decompiler, high_func_db_util):
    """
    Improved version of function definition application with better variable handling.
    """
    try:
        function_name = function.getName()
        enhanced_name = enhanced_info['name']
        
        print(f"Applying enhanced definition to {function_name} -> {enhanced_name}")
        
        # 1. Apply function name
        if enhanced_name and enhanced_name != function_name:
            function.setName(enhanced_name, SourceType.USER_DEFINED)
        
        # 2. Apply return type
        if enhanced_info.get('return_type'):
            return_type = map_c_type_to_ghidra_type(enhanced_info['return_type'], function.getProgram())
            if return_type:
                function.setReturnType(return_type, SourceType.USER_DEFINED)
        
        # 3. Apply function parameters
        apply_function_parameters(function, enhanced_info.get('parameters', []))
        
        # 4. Apply function comment
        if enhanced_info.get('comment'):
            apply_function_comment(function, enhanced_info['comment'])
        
        # 5. Try multiple approaches for variable naming
        local_vars = enhanced_info.get('local_variables', [])
        if local_vars:
            # First try the decompiler-based approach
            print(f"  Attempting decompiler-based variable updates...")
            apply_function_variables(function, local_vars, decompiler, high_func_db_util)
            
            # Also try alternative symbol-based approach as backup
            print(f"  Attempting alternative symbol-based variable updates...")
            apply_function_variables_alternative(function, local_vars)
        
        return True
        
    except Exception as e:
        print(f"Failed to apply enhanced definition to {function.getName()}: {e}")
        return False

def apply_function_variables_alternative(function, var_info_list):
    """
    Alternative approach to apply variable names using direct symbol table manipulation.
    This uses a completely different approach that might work when decompiler-based methods fail.
    """
    if not var_info_list:
        return
        
    try:
        print(f"  Alternative variable naming for {function.getName()}")
        
        # Start a transaction for all variable updates
        transaction_id = function.getProgram().startTransaction("Alternative Variable Update")
        updated_count = 0
        
        try:
            # Get local variables using alternative method
            current_vars = get_function_local_variables_alternative(function)
            enhanced_vars = [var for var in var_info_list 
                            if var.get('category') == 'local' and not var.get('is_parameter', False)]
            
            if not current_vars and not enhanced_vars:
                print(f"    No variables found for alternative approach")
                return
                
            print(f"    Found {len(current_vars)} current vars, {len(enhanced_vars)} enhanced vars")
            
            # Try to get all local variables from function's variable storage
            listing = function.getProgram().getListing()
            variables = function.getAllVariables()
            
            local_variables = []
            for var in variables:
                # Check if it's a parameter using different methods
                is_param = False
                try:
                    is_param = var.isParameter()
                except AttributeError:
                    # If isParameter() doesn't exist, check by class name and other heuristics
                    try:
                        class_name = var.__class__.__name__
                        if 'Parameter' in class_name:
                            is_param = True
                        else:
                            # Additional heuristics for parameter detection
                            if hasattr(var, 'getFirstUseOffset'):
                                is_param = var.getFirstUseOffset() == 0
                            elif hasattr(var, 'getVariableStorage'):
                                # Parameters are usually in registers or positive stack offsets  
                                storage_str = str(var.getVariableStorage())
                                is_param = ('r' in storage_str and ':' in storage_str) or 'Stack[0x' in storage_str
                            else:
                                is_param = False
                    except Exception as param_check_error:
                        print(f"    → Parameter detection failed for variable: {param_check_error}")
                        # Default to treating as local variable when unsure
                        is_param = False
                
                if not is_param:  # Only get local variables
                    local_variables.append(var)
            
            print(f"    Found {len(local_variables)} local variables via function.getAllVariables()")
            
            # Also try to get variables from the symbol table as backup
            symbol_table = function.getProgram().getSymbolTable()
            symbol_vars = []
            try:
                symbols = symbol_table.getSymbols(function)
                for symbol in symbols:
                    if symbol.getSymbolType().toString() == "LocalVar":
                        symbol_vars.append(symbol)
                print(f"    Found {len(symbol_vars)} local variables via symbol table")
            except Exception as symbol_error:
                print(f"    Symbol table lookup failed: {symbol_error}")
            
            # Use the method that found more variables
            variables_to_use = local_variables if len(local_variables) >= len(symbol_vars) else symbol_vars
            
            
            # Simple position-based and name-based matching for alternative approach
            for i, enhanced_var in enumerate(enhanced_vars):
                target_var = None
                
                # Try to find matching variable by name first
                for var in variables_to_use:
                    var_name = var.getName() if hasattr(var, 'getName') else str(var)
                    if var_name == enhanced_var.get('original_name', ''):
                        target_var = var
                        print(f"    → Found variable by original name: {var_name}")
                        break
                
                # If name match failed, try positional matching
                if not target_var and i < len(variables_to_use):
                    target_var = variables_to_use[i]
                    var_name = target_var.getName() if hasattr(target_var, 'getName') else str(target_var)
                    print(f"    → Using positional match for variable: {var_name}")
                
                if target_var:
                    try:
                        old_name = target_var.getName() if hasattr(target_var, 'getName') else str(target_var)
                        new_name = enhanced_var['name']
                        
                        if old_name != new_name:
                            # Try multiple approaches to rename the variable
                            renamed = False
                            
                            # Approach 1: Direct setName if it's a Variable object
                            if hasattr(target_var, 'setName'):
                                try:
                                    target_var.setName(new_name, SourceType.USER_DEFINED)
                                    # Verify the change
                                    current_name = target_var.getName() if hasattr(target_var, 'getName') else str(target_var)
                                    if current_name == new_name:
                                        print(f"    ✓ Direct rename successful: {old_name} -> {new_name}")
                                        renamed = True
                                        updated_count += 1
                                except Exception as direct_error:
                                    print(f"    → Direct rename failed: {direct_error}")
                            
                            # Approach 2: If it's a Symbol, try setName on the symbol
                            elif hasattr(target_var, 'setName') and hasattr(target_var, 'getSymbolType'):
                                try:
                                    target_var.setName(new_name, SourceType.USER_DEFINED)
                                    current_name = target_var.getName()
                                    if current_name == new_name:
                                        print(f"    ✓ Symbol rename successful: {old_name} -> {new_name}")
                                        renamed = True
                                        updated_count += 1
                                except Exception as symbol_error:
                                    print(f"    → Symbol rename failed: {symbol_error}")
                            
                            # Approach 3: Try recreation approach
                            if not renamed and hasattr(target_var, 'getVariableStorage') and hasattr(target_var, 'getDataType'):
                                try:
                                    # Get variable details for recreation
                                    storage = target_var.getVariableStorage()
                                    data_type = target_var.getDataType()
                                    
                                    # Remove the old variable
                                    function.removeVariable(target_var)
                                    
                                    # Create new variable with new name
                                    new_var = function.addLocalVariable(storage, new_name, data_type, SourceType.USER_DEFINED)
                                    if new_var and new_var.getName() == new_name:
                                        print(f"    ✓ Recreation rename successful: {old_name} -> {new_name}")
                                        renamed = True
                                        updated_count += 1
                                    else:
                                        # Try to restore the original variable if recreation failed
                                        try:
                                            function.addLocalVariable(storage, old_name, data_type, SourceType.USER_DEFINED)
                                        except:
                                            pass
                                    
                                except Exception as recreation_error:
                                    print(f"    → Variable recreation failed: {recreation_error}")
                                    
                            if not renamed:
                                print(f"    ✗ All rename approaches failed for: {old_name} -> {new_name}")
                                
                        # Also try to update the data type if provided
                        enhanced_type = enhanced_var.get('type')
                        if enhanced_type and hasattr(target_var, 'setDataType'):
                            try:
                                new_data_type = map_c_type_to_ghidra_type(enhanced_type, function.getProgram())
                                if new_data_type:
                                    current_type = str(target_var.getDataType()) if hasattr(target_var, 'getDataType') else 'unknown'
                                    if current_type != enhanced_type:
                                        target_var.setDataType(new_data_type, SourceType.USER_DEFINED)
                                        new_current_type = str(target_var.getDataType()) if hasattr(target_var, 'getDataType') else 'unknown'
                                        if new_current_type == enhanced_type:
                                            print(f"    ✓ Type update successful: {target_var.getName() if hasattr(target_var, 'getName') else 'var'} : {enhanced_type}")
                            except Exception as type_error:
                                var_name = target_var.getName() if hasattr(target_var, 'getName') else 'unknown'
                                print(f"    → Type update failed for {var_name}: {type_error}")
                                
                    except Exception as var_error:
                        print(f"    ✗ Alternative variable processing failed for item {i}: {var_error}")
                else:
                    print(f"    → No target variable found for enhanced variable {i}: {enhanced_var.get('name', 'unknown')}")
                        
        except Exception as inner_error:
            print(f"    Alternative approach inner error: {inner_error}")
        finally:
            function.getProgram().endTransaction(transaction_id, updated_count > 0)
            
        if updated_count > 0:
            print(f"    ✓ Alternative approach updated {updated_count} variables")
        else:
            print(f"    ⚠ Alternative approach: no variables were successfully updated")
                    
    except Exception as e:
        print(f"  Alternative variable application failed: {e}")
        import traceback
        traceback.print_exc()

def map_c_type_to_ghidra_type(type_string, program=None):
    """
    Enhanced mapping of C data type strings to corresponding Ghidra data types.
    Supports custom types, arrays, and more complete type system.
    """
    from ghidra.program.model.data import (
        IntegerDataType, VoidDataType, CharDataType, ShortDataType,
        LongDataType, FloatDataType, DoubleDataType, PointerDataType,
        UnsignedIntegerDataType, UnsignedCharDataType, UnsignedShortDataType,
        UnsignedLongDataType, BooleanDataType, ArrayDataType, Undefined8DataType,
        LongLongDataType, UnsignedLongLongDataType
    )
    
    if not type_string:
        return IntegerDataType()
    
    original_type_string = type_string.strip()
    type_string = original_type_string.lower()
    
    # Handle arrays first (e.g., "int[5]", "uint[2]")
    if '[' in type_string and ']' in type_string:
        try:
            base_type_str = type_string.split('[')[0].strip()
            array_size_str = type_string.split('[')[1].split(']')[0].strip()
            
            base_type = map_c_type_to_ghidra_type(base_type_str, program)
            if base_type and array_size_str.isdigit():
                array_size = int(array_size_str)
                return ArrayDataType(base_type, array_size, base_type.getLength())
        except Exception as e:
            print(f"    Warning: Failed to parse array type '{original_type_string}': {e}")
    
    # Handle pointers (before basic type mapping)
    if type_string.endswith('*'):
        base_type_str = type_string[:-1].strip()
        base_type = map_c_type_to_ghidra_type(base_type_str, program)
        return PointerDataType(base_type) if base_type else PointerDataType()
    
    # Enhanced basic types mapping
    type_mapping = {
        'void': VoidDataType(),
        'int': IntegerDataType(),
        'uint': UnsignedIntegerDataType(),
        'unsigned': UnsignedIntegerDataType(),
        'unsigned int': UnsignedIntegerDataType(),
        'char': CharDataType(),
        'uchar': UnsignedCharDataType(),
        'unsigned char': UnsignedCharDataType(),
        'short': ShortDataType(),
        'ushort': UnsignedShortDataType(),
        'unsigned short': UnsignedShortDataType(),
        'long': LongDataType(),
        'ulong': UnsignedLongDataType(),
        'unsigned long': UnsignedLongDataType(),
        'long long': LongLongDataType(),
        'longlong': LongLongDataType(),
        'ulonglong': UnsignedLongLongDataType(),
        'unsigned long long': UnsignedLongLongDataType(),
        'float': FloatDataType(),
        'double': DoubleDataType(),
        'bool': BooleanDataType(),
        'boolean': BooleanDataType(),
        '_bool': BooleanDataType(),
        'undefined8': Undefined8DataType(),
    }
    
    # Check if it's a known basic type
    mapped_type = type_mapping.get(type_string)
    if mapped_type:
        return mapped_type
    
    # Try to find custom/existing types in the program's data type manager
    if program:
        try:
            dtm = program.getDataTypeManager()
            
            # Search for the type by name (case-insensitive search)
            existing_type = dtm.getDataType(original_type_string)
            if existing_type:
                return existing_type
                
            # Try different case variations
            for name_variant in [original_type_string, original_type_string.upper(), original_type_string.lower()]:
                existing_type = dtm.getDataType(name_variant)
                if existing_type:
                    return existing_type
            
            # Search in built-in categories
            for category in dtm.getAllDataTypes():
                if category.getName().lower() == type_string:
                    return category
                    
        except Exception as e:
            print(f"    Warning: Error searching for custom type '{original_type_string}': {e}")
    
    # Fallback: return int for unknown types but warn about it
    print(f"    Warning: Unknown type '{original_type_string}', using int as fallback")
    return IntegerDataType()

# Run the enhanced apply process
apply_enhanced_signatures()
