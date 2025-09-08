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
        
        # Pre-analyze for potential conflicts
        enhanced_name_counts = {}
        for enhanced in enhanced_vars:
            name = enhanced['name']
            enhanced_name_counts[name] = enhanced_name_counts.get(name, 0) + 1
        
        duplicate_names = {name: count for name, count in enhanced_name_counts.items() if count > 1}
        if duplicate_names:
            print(f"    ⚠ Warning: Enhanced data contains duplicate variable names: {duplicate_names}")
            print("    → These will be automatically numbered to prevent conflicts")
        
        # Debug: Show current and enhanced variables
        if current_symbols:
            print("    Current variables:")
            for i, current in enumerate(current_symbols):
                print(f"      {i+1}. {current['name']} : {current['type']} (storage: {current['storage']})")
        
        if enhanced_vars:
            print("    Enhanced variables:")
            for i, enhanced in enumerate(enhanced_vars):
                print(f"      {i+1}. {enhanced['name']} : {enhanced['type']} (storage: {enhanced.get('storage', 'N/A')})")
        
        # Track names that will be used to prevent conflicts
        reserved_names = set()
        # Add existing names from symbols we won't modify
        for symbol in local_symbols:
            reserved_names.add(symbol.getName())
        
        # Track matched symbols and enhanced vars to prevent double-matching
        matched_symbols = set()
        used_enhanced_vars = set()
        
        # Strategy 1: Try to match by storage location (most reliable)
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
                            # Update reserved names
                            reserved_names.discard(current['name'])  # Remove old name
                            reserved_names.add(enhanced['name'])     # Add new name
                            print(f"    Storage match: {current['name']} -> {enhanced['name']}")
                        break
        
        # Strategy 2: Try to match by name (for variables that weren't renamed)
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
                        print(f"    Name match: {current['name']} -> {enhanced['name']}")
                    break
        
        # Strategy 3: Try to match by type (for similar variables)
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
                        # Update reserved names
                        reserved_names.discard(current['name'])  # Remove old name
                        reserved_names.add(enhanced['name'])     # Add new name
                        print(f"    Type match: {current['name']} -> {enhanced['name']}")
                    break
        
        # Strategy 4: Match remaining variables by position (order)
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
                    # Update reserved names
                    reserved_names.discard(current['name'])  # Remove old name
                    reserved_names.add(enhanced['name'])     # Add new name
                    print(f"    Position match: {current['name']} -> {enhanced['name']}")
        
        total_matched = len(matched_symbols)
        print(f"  Applied {total_matched} variable updates to {function.getName()}")
        
    except Exception as e:
        print(f"  Failed to apply variables to {function.getName()}: {e}")

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
        
        # Apply the update using improved approach
        success = False
        
        try:
            # Method 1: Try updateDBVariable with the enhanced approach
            # Handle the most problematic cases first
            
            if name_needs_update and type_needs_update:
                # Update both name and type - most likely to cause conflicts
                try:
                    high_func_db_util.updateDBVariable(
                        symbol, final_name, data_type, SourceType.USER_DEFINED
                    )
                except Exception as name_type_error:
                    print(f"    ✗ Combined update failed: {name_type_error}")
                    # Try type-only update as fallback
                    try:
                        high_func_db_util.updateDBVariable(
                            symbol, old_name, data_type, SourceType.USER_DEFINED
                        )
                        print(f"    ⚠ Applied type update only (name update failed due to: {name_type_error})")
                    except Exception as type_fallback_error:
                        print(f"    ✗ Type-only fallback also failed: {type_fallback_error}")
                        success = False
                        
            elif type_needs_update:
                # Just update type, keep the name - usually safer
                high_func_db_util.updateDBVariable(
                    symbol, old_name, data_type, SourceType.USER_DEFINED
                )
                
            elif name_needs_update:
                # Just update name, keep the type - check for duplicates again
                try:
                    high_func_db_util.updateDBVariable(
                        symbol, final_name, symbol.getDataType(), SourceType.USER_DEFINED
                    )
                except Exception as name_error:
                    if "DuplicateNameException" in str(name_error):
                        print(f"    ✗ Name update failed due to duplicate: {name_error}")
                        print(f"    → Keeping original name '{old_name}'")
                        success = False
                    else:
                        raise name_error
            
            # Force commit the changes immediately
            if high_func:
                try:
                    high_func_db_util.commitLocalNamesToDatabase(
                        high_func, SourceType.USER_DEFINED
                    )
                except:
                    pass  # This might fail in some cases, but that's okay
                
                try:
                    high_func_db_util.commitParamsToDatabase(
                        high_func,
                        True,  # overwrite existing
                        HighFunctionDBUtil.ReturnCommitOption.COMMIT,
                        SourceType.USER_DEFINED
                    )
                except:
                    pass  # This might fail in some cases, but that's okay
            
            # Verify the update worked by checking the symbol again
            updated_name = symbol.getName()
            updated_type = str(symbol.getDataType())
            
            name_updated = (updated_name == final_name) or not name_needs_update
            type_updated = (updated_type == new_type) or not type_needs_update
            
            if name_updated and type_updated:
                success = True
                print(f"    ✓ Successfully updated: {updated_name} : {updated_type}")
            else:
                # Determine what actually got updated
                partial_success = False
                status_parts = []
                
                if name_needs_update:
                    if updated_name == final_name:
                        status_parts.append("Name ✓")
                        partial_success = True
                    else:
                        status_parts.append(f"Name ✗ ('{updated_name}' ≠ '{final_name}')")
                
                if type_needs_update:
                    if updated_type == new_type:
                        status_parts.append("Type ✓")
                        partial_success = True
                    else:
                        status_parts.append(f"Type ✗ ('{updated_type}' ≠ '{new_type}')")
                
                status_msg = ", ".join(status_parts)
                if partial_success:
                    print(f"    ⚠ Partial success - {status_msg}")
                    if name_needs_update and updated_name != final_name:
                        print(f"    → Type update successful, but name update failed (this is a known Ghidra limitation)")
                    success = True  # Consider partial success as success
                else:
                    print(f"    ✗ Update failed: {status_msg}")
            
        except Exception as e:
            print(f"    ✗ updateDBVariable failed: {e}")
            
            # Fallback: Try alternative approach for type-only updates
            if type_needs_update and not name_needs_update:
                try:
                    # Sometimes we can set the data type directly
                    symbol.setDataType(data_type, SourceType.USER_DEFINED)
                    if str(symbol.getDataType()) == new_type:
                        print(f"    ✓ Fallback type update successful: {old_name} : {new_type}")
                        success = True
                except Exception as fallback_e:
                    print(f"    ✗ Fallback type update also failed: {fallback_e}")
            
            if not success:
                success = False
        
        return success
        
    except Exception as e:
        print(f"    ✗ Failed to update variable {symbol.getName()}: {e}")
        import traceback
        traceback.print_exc()
        return False

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
