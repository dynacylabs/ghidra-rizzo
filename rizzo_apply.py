# @runtime PyGhidra

# Apply enhanced function signatures with multi-stage matching
# @author fuzzywalls
# @category TNS
# @menupath TNS.Rizzo.Apply Enhanced Signatures

import pickle
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
except ImportError:
    # Fallback to basic type mapping if rizzo_type_utils is not available
    def map_c_type_to_ghidra_type(type_string):
        from ghidra.program.model.data import IntegerDataType
        return IntegerDataType()

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
    
    print('Applying enhanced signatures...')
    
    # Create Rizzo instance for the current program
    current_rizz = rizzo.Rizzo(currentProgram)
    
    # Find matches using the original signatures
    signature_matches = current_rizz._find_match(enhanced_data['rizzo_signatures'])
    
    # Set up components for applying enhanced function definitions
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    high_func_db_util = HighFunctionDBUtil()
    
    enhanced_count = 0
    renamed_count = 0
    variable_updates = 0
    
    # Process all signature matches
    for match_group in signature_matches:
        if not match_group:
            continue
            
        for curr_func, matched_func in match_group.items():
            try:
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
                    success = apply_enhanced_function_definition(
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
                print(f"Error applying enhanced signature: {e}")
                continue
    
    decompiler.dispose()
    
    print(f"Applied enhanced definitions to {enhanced_count} functions")
    print(f"Renamed {renamed_count} functions")
    print(f"Applied variable updates for {variable_updates} variables")

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
            return_type = map_c_type_to_ghidra_type(enhanced_info['return_type'])
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
            param_type = map_c_type_to_ghidra_type(param_info['type'])
            if param_type:
                parameter = ParameterImpl(param_info['name'], param_type, currentProgram)
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
        
        # Debug: Show current and enhanced variables
        if current_symbols:
            print("    Current variables:")
            for i, current in enumerate(current_symbols):
                print(f"      {i+1}. {current['name']} : {current['type']} (storage: {current['storage']})")
        
        if enhanced_vars:
            print("    Enhanced variables:")
            for i, enhanced in enumerate(enhanced_vars):
                print(f"      {i+1}. {enhanced['name']} : {enhanced['type']} (storage: {enhanced.get('storage', 'N/A')})")
        
        # Strategy 1: Try to match by storage location (most reliable)
        matched_by_storage = set()
        matched_enhanced_storage = set()
        for current in current_symbols:
            if current['symbol'] in matched_by_storage:
                continue
                
            current_storage = current['storage']
            if current_storage and current_storage != "":
                for enhanced in enhanced_vars:
                    enhanced_storage = enhanced.get('storage', '')
                    if enhanced_storage == current_storage and enhanced_storage not in matched_enhanced_storage:
                        success = apply_variable_update(current['symbol'], enhanced, high_func, high_func_db_util, function)
                        if success:
                            matched_by_storage.add(current['symbol'])
                            matched_enhanced_storage.add(enhanced_storage)
                            print(f"    Storage match: {current['name']} -> {enhanced['name']}")
                        break
        
        # Strategy 2: Try to match by name (for variables that weren't renamed)
        matched_by_name = set()
        matched_enhanced_name = set()
        for current in current_symbols:
            if current['symbol'] in matched_by_storage:
                continue
                
            current_name = current['name']
            for enhanced in enhanced_vars:
                enhanced_name = enhanced['name']
                if enhanced_name == current_name and enhanced_name not in matched_enhanced_name:
                    success = apply_variable_update(current['symbol'], enhanced, high_func, high_func_db_util, function)
                    if success:
                        matched_by_name.add(current['symbol'])
                        matched_enhanced_name.add(enhanced_name)
                        print(f"    Name match: {current['name']} -> {enhanced['name']}")
                    break
        
        # Strategy 3: Try to match by type (for similar variables)
        matched_by_type = set()
        matched_enhanced_type = set()
        for current in current_symbols:
            if current['symbol'] in matched_by_storage or current['symbol'] in matched_by_name:
                continue
                
            current_type = current['type']
            for enhanced in enhanced_vars:
                enhanced_type = enhanced['type']
                enhanced_key = f"{enhanced_type}_{enhanced['name']}"  # Use unique key for tracking
                if enhanced_type == current_type and enhanced_key not in matched_enhanced_type:
                    success = apply_variable_update(current['symbol'], enhanced, high_func, high_func_db_util, function)
                    if success:
                        matched_by_type.add(current['symbol'])
                        matched_enhanced_type.add(enhanced_key)
                        print(f"    Type match: {current['name']} -> {enhanced['name']}")
                    break
        
        # Strategy 4: Match remaining variables by position (order)
        remaining_current = [c for c in current_symbols if c['symbol'] not in matched_by_storage and c['symbol'] not in matched_by_name and c['symbol'] not in matched_by_type]
        remaining_enhanced = [e for e in enhanced_vars if e.get('storage', '') not in matched_enhanced_storage and e['name'] not in matched_enhanced_name and f"{e['type']}_{e['name']}" not in matched_enhanced_type]
        
        for i, current in enumerate(remaining_current):
            if i < len(remaining_enhanced):
                enhanced = remaining_enhanced[i]
                success = apply_variable_update(current['symbol'], enhanced, high_func, high_func_db_util, function)
                if success:
                    print(f"    Position match: {current['name']} -> {enhanced['name']}")
        
        total_matched = len(matched_by_storage) + len(matched_by_name) + len(matched_by_type) + min(len(remaining_current), len(remaining_enhanced))
        print(f"  Applied {total_matched} variable updates to {function.getName()}")
        
    except Exception as e:
        print(f"  Failed to apply variables to {function.getName()}: {e}")

def apply_variable_update(symbol, enhanced_var, high_func, high_func_db_util, function):
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
        data_type = map_c_type_to_ghidra_type(new_type)
        if not data_type:
            print(f"    Warning: Could not map type '{new_type}' for variable {old_name}")
            return False
        
        # Show what we're updating
        if name_needs_update and type_needs_update:
            print(f"    Updating variable: {old_name} ({old_type}) -> {new_name} ({new_type})")
        elif name_needs_update:
            print(f"    Renaming variable: {old_name} -> {new_name}")
        elif type_needs_update:
            print(f"    Retyping variable: {old_name} ({old_type}) -> ({new_type})")
        
        # For HighSymbol, we need to use updateDBVariable method differently
        # The key insight is that we need to pass BOTH the name and type, 
        # even if only one is changing
        success = False
        
        try:
            # Always pass the new name (even if it's the same) and new data type
            high_func_db_util.updateDBVariable(
                symbol, new_name, data_type, SourceType.USER_DEFINED
            )
            
            # Commit the changes to make them persistent
            # Use COMMIT_LOCALS option specifically for local variables
            high_func_db_util.commitLocalNamesToDatabase(
                high_func, SourceType.USER_DEFINED
            )
            
            high_func_db_util.commitParamsToDatabase(
                high_func,
                True,
                HighFunctionDBUtil.ReturnCommitOption.COMMIT,
                SourceType.USER_DEFINED,
            )
            
            # Verify the update worked by checking the symbol again
            updated_name = symbol.getName()
            updated_type = str(symbol.getDataType())
            
            name_updated = updated_name == new_name or not name_needs_update
            type_updated = updated_type == new_type or not type_needs_update
            
            if name_updated and type_updated:
                success = True
                print(f"    ✓ Successfully updated: {updated_name} : {updated_type}")
            else:
                print(f"    ⚠ Partial success - Name: '{updated_name}' (wanted '{new_name}'), Type: '{updated_type}' (wanted '{new_type}')")
                # If type updated but name didn't, that's still partial success
                if type_updated and not name_updated:
                    print(f"    → Type update successful, but name update failed (this is a known Ghidra limitation)")
                success = type_updated  # Consider it successful if at least type worked
            
        except Exception as e:
            print(f"    ✗ updateDBVariable failed: {e}")
            success = False
        
        return success
        
    except Exception as e:
        print(f"    ✗ Failed to update variable {symbol.getName()}: {e}")
        import traceback
        traceback.print_exc()
        return False

def map_c_type_to_ghidra_type(type_string):
    """
    Map C data type strings to corresponding Ghidra data types.
    This is a simplified version - you may want to import the full version from ai_auto_analysis.py
    """
    from ghidra.program.model.data import (
        IntegerDataType, VoidDataType, CharDataType, ShortDataType,
        LongDataType, FloatDataType, DoubleDataType, PointerDataType,
        UnsignedIntegerDataType, UnsignedCharDataType, UnsignedShortDataType,
        UnsignedLongDataType, BooleanDataType
    )
    
    if not type_string:
        return IntegerDataType()
    
    type_string = type_string.strip().lower()
    
    # Handle basic types
    type_mapping = {
        'void': VoidDataType(),
        'int': IntegerDataType(),
        'char': CharDataType(),
        'short': ShortDataType(),
        'long': LongDataType(),
        'float': FloatDataType(),
        'double': DoubleDataType(),
        'unsigned int': UnsignedIntegerDataType(),
        'unsigned char': UnsignedCharDataType(),
        'unsigned short': UnsignedShortDataType(),
        'unsigned long': UnsignedLongDataType(),
        'bool': BooleanDataType(),
        'boolean': BooleanDataType(),
    }
    
    # Handle pointers
    if type_string.endswith('*'):
        base_type = map_c_type_to_ghidra_type(type_string[:-1].strip())
        return PointerDataType(base_type) if base_type else PointerDataType()
    
    return type_mapping.get(type_string, IntegerDataType())

# Run the enhanced apply process
apply_enhanced_signatures()
