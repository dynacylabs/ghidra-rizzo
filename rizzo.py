import os
import time
import pickle

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.symbol import SourceType
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import RefType
from ghidra.program.model.data import DataTypeManager
from ghidra.program.model.listing import ParameterImpl, LocalVariableImpl, Function, CodeUnit
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.app.decompiler import DecompInterface


def get_instruction_list(code_manager, function):
    """
    Get list of instructions in the function.

    :param function: Function to parse for instruction list.

    :returns: List of instructions.
    """
    if function is None:
        return []
    function_bounds = function.getBody()
    function_instructions = code_manager.getInstructions(function_bounds, True)
    return function_instructions


def get_function(function_manager, address):
    """
    Return the function that contains the address. 

    :param address: Address within function.

    :returns: Function that contains the provided address.
    """
    return function_manager.getFunctionContaining(address)


def is_call_instruction(instruction):
    """
    Determine if an instruction calls a function.

    :param instruction: Instruction to inspect.
    :type instruction: ghidra.program.model.listing.Instruction

    :returns: True if the instruction is a call, false otherwise.
    :rtype: bool
    """
    if not instruction:
        return False

    flow_type = instruction.getFlowType()
    return flow_type.isCall()


def is_jump_instruction(instruction):
    """
    Determine if instruction is a jump.

    :param instruction: Instruction to inspect.
    :type instruction: ghidra.program.model.listing.Instruction

    :returns: True if the instruction is a jump, false otherwise.
    :rtype: bool
    """
    if not instruction:
        return False

    flow_type = instruction.getFlowType()
    return flow_type.isJump()


def get_processor(current_program):
    """
    Get string representing the current programs processor.

    :param current_program: Current program loaded in Ghidra.
    :type current_program: ghidra.program.model.listing.Program.
    """
    language = current_program.getLanguage()
    return language.getProcessor().toString()


def find_function(current_program, function_name):
    """
    Find a function, by name, in the current program.

    :param current_program: Current program loaded in Ghidra.
    :type current_program: ghidra.program.model.listing.Program

    :param function_name: Function to search for.
    :type function_name: str
    """
    listing = current_program.getListing()
    if listing:
        return listing.getGlobalFunctions(function_name)
    return []


def address_to_int(address):
    """
    Convert Ghidra address to integer.

    :param address: Address to convert to integer.
    :type address: ghidra.program.model.address.Address

    :returns: Integer representation of the address.
    :rtype: int
    """
    return int(address.toString(), 16)


def allowed_processors(current_program, processor_list):
    """
    Function to prevent scripts from running against unsupported processors.

    :param current_program: Current program loaded in Ghidra.
    :type current_program: ghidra.program.model.listing.Program

    :param processor_list: List of supported processors.
    :type processor_list: list(str)
    """
    curr_processor = get_processor(current_program)

    if curr_processor not in processor_list:
        print("{current_processor} is not a valid processor for this script. Supported ' \
            'processors are: {suppored_processors}".format(current_processor=curr_processor,
                                                           supported_procesors=processor_list))
        exit(1)


def table_pretty_print(title, entries):
    """
    Print a simple table to the terminal.

    :param title: Title of the table.
    :type title: list

    :param entries: Entries to print in the table.
    :type entries: list(list(str))
    """
    # Pad entries to be the same length
    entries = [entry + ([''] * (len(title) - len(entry))) for entry in entries]
    lines = [title] + entries

    # Find the largest entry in each column so it can be used later
    # for the format string. Drop title entries if an entire column is empty.
    max_line_len = []
    for i in range(0, len(title)):
        column_lengths = [len(line[i]) for line in lines]
        if sum(column_lengths[1:]) == 0:
            title = title[:i]
            break
        max_line_len.append(max(column_lengths))

    # Account for largest entry, spaces, and '|' characters on each line.
    separator = '=' * (sum(max_line_len) + (len(title) * 3) + 1)
    spacer = '|'
    format_specifier = '{:<{width}}'

    # First block prints the title and '=' characters to make a title
    # border
    print(separator)
    print(spacer)

    for width, column in zip(max_line_len, title):
        print_string = spacer
        print_string += format_specifier.format(column, width=width)
        print_string += spacer

    print(print_string)
    print("")
    print(separator)

    # Print the actual entries.
    for entry in entries:
        print(spacer)
        print_string = ""
        for width, column in zip(max_line_len, entry):
            print_string += format_specifier.format(column, width=width)
            print_string += spacer
        print("")
    print(separator)


def is_code_ref(reference):
    """
    Determine if the reference is code reference.

    :param reference: Reference to inspect.
    :type reference: ghidra.program.model.symbol.Reference

    :returns: True if reference is a code reference, False otherwise.
    :rtype: bool
    """
    ref_type = reference.getReferenceType()
    if ref_type:
        return ref_type.isCall() or ref_type.isConditional() or ref_type.isJump()
    return False


def is_data_ref(reference):
    """
    Determine if the reference is a data reference.

    :param reference: Reference to inspect.
    :type reference: ghidra.program.model.symbol.Reference

    :returns: True if reference is a data reference, False otherwise.
    :rtype: bool
    """
    ref_type = reference.getReferenceType()
    if ref_type:
        return ref_type.isRead() or ref_type.isData()
    return False


def is_call_instruction(instruction):
    """
    Determine if the reference is a function call.

    :param reference: Reference to inspect.
    :type reference: ghidra.program.model.symbol.Reference

    :returns: True if reference is function call, False otherwise.
    :rtype: bool
    """
    flow_type = instruction.getFlowType()
    if flow_type:
        return flow_type.isCall()
    return False


def extract_function_signature(function):
    """
    Extract function signature information including return type and parameters.
    
    :param function: Function to extract signature from.
    :type function: ghidra.program.model.listing.Function
    
    :returns: Dictionary containing signature information.
    :rtype: dict
    """
    if not function:
        return None
        
    signature_data = {
        'return_type': None,
        'calling_convention': None,
        'parameters': []
    }
    
    try:
        # Get return type
        return_type = function.getReturnType()
        if return_type:
            signature_data['return_type'] = return_type.getName()
        
        # Get calling convention
        calling_convention = function.getCallingConventionName()
        if calling_convention:
            signature_data['calling_convention'] = calling_convention
            
        # Get parameters
        parameters = function.getParameters()
        for param in parameters:
            param_data = {
                'name': param.getName(),
                'data_type': param.getDataType().getName() if param.getDataType() else None,
                'ordinal': param.getOrdinal(),
                'comment': param.getComment()
            }
            signature_data['parameters'].append(param_data)
            
    except Exception as e:
        print("Warning: Could not extract complete signature for function {}: {}".format(
            function.getName() if function else "Unknown", str(e)))
    
    return signature_data


def extract_function_variables(function, program=None):
    """
    Extract comprehensive variable information from a function using high-level function analysis.
    
    :param function: Function to extract variables from.
    :type function: ghidra.program.model.listing.Function
    
    :param program: Current program (needed for decompiler interface)
    :type program: ghidra.program.model.listing.Program
    
    :returns: Dictionary containing all variable information including high-level symbols.
    :rtype: dict
    """
    if not function:
        return {}
        
    variables_data = {
        'parameters': [],
        'local_variables': [],
        'high_level_symbols': []
    }
    
    try:
        # Extract function parameters (more robust than before)
        parameters = function.getParameters()
        for param in parameters:
            param_data = {
                'name': param.getName(),
                'data_type': param.getDataType().getName() if param.getDataType() else None,
                'ordinal': param.getOrdinal(),
                'comment': param.getComment(),
                'storage': str(param.getVariableStorage()) if hasattr(param, 'getVariableStorage') else None,
                'length': param.getLength()
            }
            variables_data['parameters'].append(param_data)
        
        # Extract local variables (basic approach for backward compatibility)
        local_variables = function.getLocalVariables()
        for var in local_variables:
            # Safely get stack offset - only call if variable has stack storage
            stack_offset = None
            try:
                if hasattr(var, 'getStackOffset') and hasattr(var, 'getVariableStorage'):
                    var_storage = var.getVariableStorage()
                    if var_storage and var_storage.hasStackStorage():
                        stack_offset = var.getStackOffset()
            except Exception:
                # If getStackOffset() fails, leave as None
                pass
            
            var_data = {
                'name': var.getName(),
                'data_type': var.getDataType().getName() if var.getDataType() else None,
                'stack_offset': stack_offset,
                'comment': var.getComment(),
                'length': var.getLength(),
                'storage': str(var.getVariableStorage()) if hasattr(var, 'getVariableStorage') else None,
            }
            variables_data['local_variables'].append(var_data)
        
        # Extract high-level symbols using decompiler interface (the robust approach)
        if program:
            decompiler = DecompInterface()
            decompiler.openProgram(program)
            try:
                # Decompile function to get high-level representation
                decompiled_result = decompiler.decompileFunction(function, 120, None)
                
                if decompiled_result and decompiled_result.decompileCompleted():
                    high_func = decompiled_result.getHighFunction()
                    if high_func:
                        # Get all symbols from the high-level function
                        local_symbols = high_func.getLocalSymbolMap().getSymbols()
                        
                        for symbol in local_symbols:
                            symbol_data = {
                                'name': symbol.getName(),
                                'data_type': symbol.getDataType().getName() if symbol.getDataType() else None,
                                'category': symbol.getCategoryString() if hasattr(symbol, 'getCategoryString') else None,
                                'storage': str(symbol.getStorage()) if hasattr(symbol, 'getStorage') else None,
                                'size': symbol.getSize() if hasattr(symbol, 'getSize') else None,
                                'is_parameter': symbol.isParameter() if hasattr(symbol, 'isParameter') else False,
                                'slot': symbol.getSlot() if hasattr(symbol, 'getSlot') else None,
                            }
                            variables_data['high_level_symbols'].append(symbol_data)
            finally:
                decompiler.dispose()
            
    except Exception as e:
        print("Warning: Could not extract complete variables for function {}: {}".format(
            function.getName() if function else "Unknown", str(e)))
    
    return variables_data


def extract_function_comments(function, program=None):
    """
    Extract comprehensive comments associated with a function using CodeUnit interface.
    
    :param function: Function to extract comments from.
    :type function: ghidra.program.model.listing.Function
    
    :param program: Current program (needed for CodeUnit access)
    :type program: ghidra.program.model.listing.Program
    
    :returns: Dictionary containing different types of comments.
    :rtype: dict
    """
    if not function:
        return {}
        
    comments = {
        'comment': None,
        'plate_comment': None,
        'pre_comment': None,
        'post_comment': None,
        'eol_comment': None,
        'repeatable_comment': None
    }
    
    try:
        # Extract basic function comments (legacy approach)
        comments['comment'] = function.getComment()
        
        # Extract comments using CodeUnit approach (more robust like ai_auto_analysis)
        if program:
            listing = program.getListing()
            entry_point = function.getEntryPoint()
            function_code_unit = listing.getCodeUnitAt(entry_point)
            
            if function_code_unit:
                comments['plate_comment'] = function_code_unit.getComment(CodeUnit.PLATE_COMMENT)
                comments['pre_comment'] = function_code_unit.getComment(CodeUnit.PRE_COMMENT)
                comments['post_comment'] = function_code_unit.getComment(CodeUnit.POST_COMMENT)
                comments['eol_comment'] = function_code_unit.getComment(CodeUnit.EOL_COMMENT)
                comments['repeatable_comment'] = function_code_unit.getComment(CodeUnit.REPEATABLE_COMMENT)
        
    except Exception as e:
        print("Warning: Could not extract complete comments for function {}: {}".format(
            function.getName() if function else "Unknown", str(e)))
    
    return comments


def apply_function_comments(function, comments_data, program=None):
    """
    Apply comprehensive comments to a function using CodeUnit interface.
    
    :param function: Function to apply comments to.
    :type function: ghidra.program.model.listing.Function
    
    :param comments_data: Comments data to apply.
    :type comments_data: dict
    
    :param program: Current program (needed for CodeUnit access)
    :type program: ghidra.program.model.listing.Program
    
    :returns: True if successful, False otherwise.
    :rtype: bool
    """
    if not function or not comments_data:
        return False
        
    success = False
    
    try:
        # Apply basic function comment (legacy approach for compatibility)
        if comments_data.get('comment'):
            try:
                function.setComment(comments_data['comment'])
                success = True
                print("  Applied function comment")
            except Exception as e:
                print("  Warning: Could not apply function comment: {}".format(str(e)))
        
        # Apply comments using CodeUnit approach (robust like ai_auto_analysis)
        if program:
            listing = program.getListing()
            entry_point = function.getEntryPoint()
            function_code_unit = listing.getCodeUnitAt(entry_point)
            
            if function_code_unit:
                # Apply plate comment (appears at top of function)
                if comments_data.get('plate_comment'):
                    try:
                        function_code_unit.setComment(CodeUnit.PLATE_COMMENT, comments_data['plate_comment'])
                        success = True
                        print("  Applied plate comment")
                    except Exception as e:
                        print("  Warning: Could not apply plate comment: {}".format(str(e)))
                
                # Apply pre comment (before function)
                if comments_data.get('pre_comment'):
                    try:
                        function_code_unit.setComment(CodeUnit.PRE_COMMENT, comments_data['pre_comment'])
                        success = True
                        print("  Applied pre comment")
                    except Exception as e:
                        print("  Warning: Could not apply pre comment: {}".format(str(e)))
                
                # Apply post comment (after function)
                if comments_data.get('post_comment'):
                    try:
                        function_code_unit.setComment(CodeUnit.POST_COMMENT, comments_data['post_comment'])
                        success = True
                        print("  Applied post comment")
                    except Exception as e:
                        print("  Warning: Could not apply post comment: {}".format(str(e)))
                
                # Apply end-of-line comment
                if comments_data.get('eol_comment'):
                    try:
                        function_code_unit.setComment(CodeUnit.EOL_COMMENT, comments_data['eol_comment'])
                        success = True
                        print("  Applied EOL comment")
                    except Exception as e:
                        print("  Warning: Could not apply EOL comment: {}".format(str(e)))
                
                # Apply repeatable comment
                if comments_data.get('repeatable_comment'):
                    try:
                        function_code_unit.setComment(CodeUnit.REPEATABLE_COMMENT, comments_data['repeatable_comment'])
                        success = True
                        print("  Applied repeatable comment")
                    except Exception as e:
                        print("  Warning: Could not apply repeatable comment: {}".format(str(e)))
        
        return success
        
    except Exception as e:
        print("Warning: Could not apply comments to function {}: {}".format(
            function.getName() if function else "Unknown", str(e)))
        return False


def apply_function_signature(function, signature_data):
    """
    Apply signature information to a function.
    
    :param function: Function to apply signature to.
    :type function: ghidra.program.model.listing.Function
    
    :param signature_data: Signature data to apply.
    :type signature_data: dict
    
    :returns: True if successful, False otherwise.
    :rtype: bool
    """
    if not function or not signature_data:
        return False
        
    success = False
    
    try:
        # Apply return type if available
        return_type_name = signature_data.get('return_type')
        if return_type_name and return_type_name != 'void':
            try:
                data_type_manager = function.getProgram().getDataTypeManager()
                return_type = data_type_manager.getDataType(return_type_name)
                if return_type:
                    function.setReturnType(return_type, SourceType.USER_DEFINED)
                    success = True
                    print("  Applied return type: {}".format(return_type_name))
            except Exception as e:
                print("  Warning: Could not apply return type {}: {}".format(return_type_name, str(e)))
        
        # Apply calling convention if available  
        calling_convention = signature_data.get('calling_convention')
        if calling_convention:
            try:
                function.setCallingConvention(calling_convention)
                success = True
                print("  Applied calling convention: {}".format(calling_convention))
            except Exception as e:
                print("  Warning: Could not apply calling convention {}: {}".format(calling_convention, str(e)))
            
        # Apply parameters if available
        parameters_data = signature_data.get('parameters', [])
        if parameters_data:
            try:
                data_type_manager = function.getProgram().getDataTypeManager()
                new_params = []
                
                for param_data in parameters_data:
                    param_name = param_data.get('name', 'param')
                    param_type_name = param_data.get('data_type')
                    param_comment = param_data.get('comment')
                    
                    if param_type_name:
                        param_type = data_type_manager.getDataType(param_type_name)
                        if param_type:
                            param = ParameterImpl(param_name, param_type, function.getProgram())
                            if param_comment:
                                param.setComment(param_comment)
                            new_params.append(param)
                
                if new_params:
                    function.replaceParameters(new_params, 
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, 
                        True, SourceType.USER_DEFINED)
                    success = True
                    print("  Applied {} parameter(s)".format(len(new_params)))
            except Exception as e:
                print("  Warning: Could not apply parameters: {}".format(str(e)))
        
        return success
        
    except Exception as e:
        print("Warning: Could not apply signature to function {}: {}".format(
            function.getName() if function else "Unknown", str(e)))
        return False


def apply_function_variables(function, variables_data, program=None):
    """
    Apply comprehensive variable information to a function using high-level function analysis.
    
    :param function: Function to apply variables to.
    :type function: ghidra.program.model.listing.Function
    
    :param variables_data: Comprehensive variables data to apply.
    :type variables_data: dict
    
    :param program: Current program (needed for decompiler interface)
    :type program: ghidra.program.model.listing.Program
    
    :returns: True if successful, False otherwise.
    :rtype: bool
    """
    if not function or not variables_data:
        return False
        
    success = False
    
    try:
        # Apply parameters (robust approach)
        parameters_data = variables_data.get('parameters', [])
        if parameters_data:
            try:
                data_type_manager = function.getProgram().getDataTypeManager()
                new_params = []
                
                for param_data in parameters_data:
                    param_name = param_data.get('name', 'param')
                    param_type_name = param_data.get('data_type')
                    param_comment = param_data.get('comment')
                    
                    if param_type_name:
                        param_type = data_type_manager.getDataType(param_type_name)
                        if param_type:
                            param = ParameterImpl(param_name, param_type, function.getProgram())
                            if param_comment:
                                param.setComment(param_comment)
                            new_params.append(param)
                
                if new_params:
                    function.replaceParameters(new_params, 
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, 
                        True, SourceType.USER_DEFINED)
                    success = True
                    print("  Applied {} parameter(s)".format(len(new_params)))
            except Exception as e:
                print("  Warning: Could not apply parameters: {}".format(str(e)))
        
        # Apply high-level symbols (the robust approach used by ai_auto_analysis)
        high_level_symbols = variables_data.get('high_level_symbols', [])
        if high_level_symbols and program:
            try:
                decompiler = DecompInterface()
                decompiler.openProgram(program)
                high_func_db_util = HighFunctionDBUtil()
                
                try:
                    # Decompile function to get high-level representation  
                    decompiled_result = decompiler.decompileFunction(function, 120, None)
                    
                    if decompiled_result and decompiled_result.decompileCompleted():
                        high_func = decompiled_result.getHighFunction()
                        if high_func:
                            # Get current symbols from the high-level function
                            current_symbols = high_func.getLocalSymbolMap().getSymbols()
                            data_type_manager = program.getDataTypeManager()
                            
                            # Create mapping of symbol names to symbol objects
                            symbol_map = {symbol.getName(): symbol for symbol in current_symbols}
                            
                            # Apply stored high-level symbol information
                            for symbol_data in high_level_symbols:
                                symbol_name = symbol_data.get('name')
                                new_type_name = symbol_data.get('data_type')
                                
                                if symbol_name in symbol_map and new_type_name:
                                    symbol = symbol_map[symbol_name]
                                    new_data_type = data_type_manager.getDataType(new_type_name)
                                    
                                    if new_data_type:
                                        try:
                                            # Update variable using high-level DB utilities
                                            high_func_db_util.updateDBVariable(
                                                symbol, symbol_name, new_data_type, SourceType.USER_DEFINED
                                            )
                                            
                                            # Commit changes to database
                                            high_func_db_util.commitParamsToDatabase(
                                                high_func,
                                                True,
                                                HighFunctionDBUtil.ReturnCommitOption.COMMIT,
                                                SourceType.USER_DEFINED,
                                            )
                                            success = True
                                            
                                        except Exception as e:
                                            print("  Warning: Could not update symbol {}: {}".format(symbol_name, str(e)))
                                            
                finally:
                    decompiler.dispose()
                    
            except Exception as e:
                print("  Warning: Could not apply high-level symbols: {}".format(str(e)))
        
        # Apply local variables (fallback/additional approach)
        local_variables_data = variables_data.get('local_variables', [])
        if local_variables_data:
            try:
                data_type_manager = function.getProgram().getDataTypeManager()
                
                for var_data in local_variables_data:
                    var_name = var_data.get('name')
                    var_type_name = var_data.get('data_type')
                    var_comment = var_data.get('comment')
                    stack_offset = var_data.get('stack_offset')
                    
                    if var_name and var_type_name:
                        var_type = data_type_manager.getDataType(var_type_name)
                        if var_type and stack_offset is not None:
                            try:
                                # Create local variable (basic approach for compatibility)
                                local_var = function.addLocalVariable(
                                    LocalVariableImpl(
                                        var_name, var_type, stack_offset, function.getProgram()),
                                    SourceType.USER_DEFINED)
                                
                                if local_var and var_comment:
                                    local_var.setComment(var_comment)
                                success = True
                                    
                            except Exception as var_e:
                                print("  Warning: Could not create variable {}: {}".format(var_name, str(var_e)))
                
            except Exception as e:
                print("  Warning: Could not apply local variables: {}".format(str(e)))
        
        return success
        
    except Exception as e:
        print("Warning: Could not apply variables to function {}: {}".format(
            function.getName() if function else "Unknown", str(e)))
        return False


def apply_function_comments(function, comments_data):
    """
    Apply comments to a function.
    
    :param function: Function to apply comments to.
    :type function: ghidra.program.model.listing.Function
    
    :param comments_data: Comments data to apply.
    :type comments_data: dict
    
    :returns: True if successful, False otherwise.
    :rtype: bool
    """
    if not function or not comments_data:
        return False
        
    try:
        if comments_data.get('comment'):
            function.setComment(comments_data['comment'])
            
        if comments_data.get('plate_comment'):
            function.setPlateComment(comments_data['plate_comment'])
            
        if comments_data.get('pre_comment'):
            function.setPreComment(comments_data['pre_comment'])
            
        if comments_data.get('post_comment'):
            function.setPostComment(comments_data['post_comment'])
        
        return True
        
    except Exception as e:
        print("Warning: Could not apply comments to function {}: {}".format(
            function.getName() if function else "Unknown", str(e)))
        return False


def find_signature_matches(new_signature, curr_signature, new_functions,
                           curr_functions, signature_type, filter_fn=None):
    """
    Search for signature matches between current file signatures and signatures
    loaded from the user provided file.

    :param new_signature: Loaded signature dictionary.
    :type new_signature: dict

    :param curr_signature: Current program signatures to compare against.
    :type curr_signature: dict

    :param new_functions: Function dict from loaded file.
    :type new_functions: dict

    :param curr_functions: Function dict from current program.
    :type curr_functions: dict

    :param signature_type: String representing the signature type.
    :type signature_type: str

    :param filter_fn: Filter function used to ignore matches under given 
                      cirumstances.
    :type filter_fn: function

    :returns: Dictionary of signatures. Key is function in current program, 
              value is the loaded function.
    :rtype: dict
    """
    signature_match = {}

    start = time.time()
    key_error_count = 0
    processed_count = 0
    total_signatures = len(new_signature)
    
    print("  Searching for {signature_type} matches in {total_sigs} signatures...".format(
        signature_type=signature_type, total_sigs=total_signatures))

    for signature, function in new_signature.iteritems():
        if signature in curr_signature:
            new_func = None
            curr_func = RizzoFunctionDescriptor(curr_signature,
                                                curr_functions,
                                                signature)
            try:
                new_func = RizzoFunctionDescriptor(new_signature,
                                                new_functions,
                                                signature)
            
                if not filter_fn or filter_fn(curr_func, new_func):
                    signature_match[curr_func] = new_func
            
            except:
                key_error_count += 1
        
        processed_count += 1
        if processed_count % 1000 == 0 or processed_count == total_signatures:
            print("    Processed {}/{} signatures ({:.1f}%)".format(
                processed_count, total_signatures,
                (processed_count * 100.0) / total_signatures if total_signatures > 0 else 0))

    end = time.time()

    print("Found {signature_match_count} {signature_type} matches in {seconds} "
          "seconds. {key_errors} Key Errors were Encountered."
          .format(signature_match_count=len(signature_match),
                  signature_type=signature_type, seconds=(end - start),
                  key_errors=key_error_count))
    return signature_match


class RizzoBlockDescriptor(object):
    """
    Break signature blocks out to classes to easily reference. Stored in this
    format to limit pickle storage space.
    """

    def __init__(self, block):
        self.formal = block[0]
        self.fuzzy = block[1]
        self.immediates = block[2]
        self.functions = block[3]

    def __eq__(self, block):
        """
        Compare this block to another to check for a match.

        :param block: Block to compare against.
        :type block: RizzoBlockDescriptor

        :returns: True if they match, false otherwise.
        :rtype: bool
        """
        return self.formal == block.formal and \
            len(self.immediates) == len(block.immediates) and \
            len(self.functions) == len(block.functions)


class RizzoFunctionDescriptor(object):
    """
    Break function descriptor out to class to easily reference. 
    """

    def __init__(self, signatures, functions, key):
        self.address = signatures[key]
        function_data = functions[self.address]
        self.name = function_data[0]
        self.blocks = function_data[1]
        # Enhanced metadata (added for enhanced functionality)
        self.signature = function_data[2] if len(function_data) > 2 else None
        self.variables = function_data[3] if len(function_data) > 3 else {}
        self.comment = function_data[4] if len(function_data) > 4 else None
        self.plate_comment = function_data[5] if len(function_data) > 5 else None
        self.pre_comment = function_data[6] if len(function_data) > 6 else None
        self.post_comment = function_data[7] if len(function_data) > 7 else None
        self.eol_comment = function_data[8] if len(function_data) > 8 else None
        self.repeatable_comment = function_data[9] if len(function_data) > 9 else None


class RizzoSignature(object):
    """
    Store discovered function signatures.
    """

    def __init__(self):
        self.formal = {}
        self.fuzzy = {}
        self.strings = {}
        self.functions = {}
        self.immediates = {}

        self.fuzzydups = set()
        self.formaldups = set()
        self.stringdups = set()
        self.functiondups = set()
        self.immediatedups = set()

    def _add(self, dictionary, dictionary_dups, key, value):
        """
        Add a signature to a dictionary or the duplicate dictionary if it 
        already exists.

        :param dictionary: Default dictionary to add entry to.
        :type dictionary: dict

        :param dictionary_dups: Duplicate dictionary to move to if already 
                                present in `dictionary`.
        :type dictionary_dups: dict

        :param key: Key to insert in dictionary.
        :type key: variable

        :parrm value: Value to set for key.
        :type: value: variable
        """
        if dictionary.has_key(key):
            del dictionary[key]
            dictionary_dups.add(key)
        elif key not in dictionary_dups:
            dictionary[key] = value

    def add_formal(self, signature, address):
        """
        Add formal function signature.

        :param signature: Signature to be added to formal signatures.
        :type signature: int

        :param address: Address of function representing the signature.
        :type address: int
        """
        self._add(self.formal, self.formaldups, signature, address)

    def add_fuzzy(self, signature, address):
        """
        Add fuzzy function signature.

        :param signature: Signature to be added to fuzzy signatures.
        :type signature: int

        :param address: Address of function representing the signature.
        :type address: int
        """
        self._add(self.fuzzy, self.fuzzydups, signature, address)

    def add_string(self, signature, address):
        """
        Add string function signature.

        :param signature: Signature to be added to string signatures.
        :type signature: int

        :param address: Address of function representing the signature.
        :type address: int
        """
        self._add(self.strings, self.stringdups, signature, address)

    def add_function(self, signature, address):
        """
        Add function call signature.

        :param signature: Signature to be added to function call signatures.
        :type signature: int

        :param address: Address of function representing the signature.
        :type address: int
        """
        self._add(self.functions, self.functiondups, signature, address)

    def add_immediate(self, signature, address):
        """
        Add immediate function signature.

        :param signature: Signature to be added to immediate signatures.
        :type signature: int

        :param address: Address of function representing the signature.
        :type address: int
        """
        self._add(self.immediates, self.immediatedups, signature, address)

    def reset_dups(self):
        """
        Reset duplicate signature sets.
        """
        self.fuzzydups = set()
        self.formaldups = set()
        self.stringdups = set()
        self.functionsdups = set()
        self.immediatedups = set()


class RizzoString(object):
    """
    Represents a found string with references to it.
    """

    def __init__(self, addr, value, references):
        self.address = addr
        self.value = value
        self.xrefs = references


class Rizzo(object):
    def __init__(self, program):
        self._program = program
        self._flat_api = FlatProgramAPI(self._program)
        self._memory_map = self._program.getMemory()
        self._simple_blk = BasicBlockModel(self._program)
        self._monitor = self._flat_api.getMonitor()
        self._function_manager = self._program.getFunctionManager()
        self._address_factory = self._program.getAddressFactory()

        self.signature_libary = None
        self.signatures = None
        self._strings = {}
        self._find_strings()

        start = time.time()
        self._signatures = self._generate()
        end = time.time()

        print("Generated {formal_signatures} formal signatures and {fuzzy_signatures} fuzzy signatures "
              "for {function_count} functions in {duration} seconds."
              .format(formal_signatures=len(self._signatures.formal),
                                            fuzzy_signatures=len(self._signatures.fuzzy),
                                            function_count=len(self._signatures.functions),
                                            duration=(end - start)))
    
    def save(self, signature_file):
        """
        Save Rizzo signatures to the supplied signature file.

        :param signature_file: Full path to save signatures.
        :type signature_file: str
        """
        print("Saving signatures to {signature_file}...".format(signature_file=signature_file))
        print("  Formal signatures: {}".format(len(self._signatures.formal)))
        print("  Fuzzy signatures: {}".format(len(self._signatures.fuzzy)))
        print("  String signatures: {}".format(len(self._signatures.strings)))
        print("  Function signatures: {}".format(len(self._signatures.functions)))
        print("  Immediate signatures: {}".format(len(self._signatures.immediates)))
        print("  Writing to file...")
        
        with open(signature_file, 'wb') as rizz_file:
            pickle.dump(self._signatures, rizz_file)
        print("Signature file saved successfully.")

    def load(self, signature_file):
        """
        Load Rizzo signatures from a file.

        :param signature_file: Full path to load signatures from.
        :type signature_file: str

        :returns: Loaded signatures
        :rtype: RizzoSignatures
        """
        if not os.path.exists(signature_file):
            raise Exception("Signature file {signature_file} does not exist".format(signature_file=signature_file))

        print("Loading signatures from {signature_file}...".format(signature_file=signature_file))
        with open(signature_file, 'rb') as rizz_file:
            try:
                signatures = pickle.load(rizz_file)
            except:
                print("This does not appear to be a Rizzo signature file.")
                exit(1)
        
        # Show what was loaded
        print("Loaded signatures successfully:")
        print("  Formal signatures: {}".format(len(signatures.formal)))
        print("  Fuzzy signatures: {}".format(len(signatures.fuzzy)))
        print("  String signatures: {}".format(len(signatures.strings)))
        print("  Function signatures: {}".format(len(signatures.functions)))
        print("  Immediate signatures: {}".format(len(signatures.immediates)))
        
        return signatures

    def apply(self, signatures):
        """
        Apply signatures to the current program.

        :param signatures: Signatures to apply to current program.
        :type signatures: RizzoSignatures
        """
        rename_count = 0
        metadata_applied_count = 0
        
        print("Finding signature matches...")
        signature_matches = self._find_match(signatures)
        renamed = []

        # Calculate total matches for progress tracking
        total_matches = sum(len(matches) for matches in signature_matches)
        processed_matches = 0
        
        print("Applying {} signature matches...".format(total_matches))

        for match_type_idx, matches in enumerate(signature_matches):
            match_type_names = ['formal', 'string', 'immediate', 'fuzzy']
            if matches:
                print("  Processing {} {} matches...".format(
                    len(matches), match_type_names[match_type_idx]))
            
            for curr_func, new_func in matches.iteritems():
                addr_hex = hex(curr_func.address)
                if addr_hex.endswith('L'):
                    addr_hex = addr_hex[:-1]
                curr_addr = self._address_factory.getAddress(addr_hex)

                function = self._flat_api.getFunctionAt(curr_addr)
                if function and new_func.name not in renamed:
                    renamed.append(new_func.name)
                    
                    print("    Applying match: {} -> {}".format(
                        function.getName(), new_func.name))
                    
                    if self._rename_functions(function, new_func.name):
                        rename_count += 1
                    
                    # Apply enhanced function metadata
                    metadata_applied = False
                    
                    # Apply function signature if available
                    if new_func.signature:
                        print("      Applying function signature...")
                        if apply_function_signature(function, new_func.signature):
                            metadata_applied = True
                    
                    # Apply function variables if available (using robust approach)
                    if new_func.variables:
                        print("      Applying function variables...")
                        if apply_function_variables(function, new_func.variables, self._program):
                            metadata_applied = True
                    
                    # Apply function comments if available (comprehensive)
                    comments_data = {
                        'comment': new_func.comment,
                        'plate_comment': new_func.plate_comment,
                        'pre_comment': new_func.pre_comment,
                        'post_comment': new_func.post_comment,
                        'eol_comment': new_func.eol_comment,
                        'repeatable_comment': new_func.repeatable_comment
                    }
                    if any(comments_data.values()):
                        print("      Applying function comments...")
                        if apply_function_comments(function, comments_data, self._program):
                            metadata_applied = True
                    
                    if metadata_applied:
                        metadata_applied_count += 1

                processed_matches += 1
                if processed_matches % 10 == 0 or processed_matches == total_matches:
                    print("  Progress: {}/{} matches processed ({:.1f}%)".format(
                        processed_matches, total_matches,
                        (processed_matches * 100.0) / total_matches if total_matches > 0 else 0))

                duplicates = []
                block_match = {}
                for block in new_func.blocks:
                    new_block = RizzoBlockDescriptor(block)
                    for curr_block in curr_func.blocks:
                        curr_block = RizzoBlockDescriptor(curr_block)

                        if curr_block == new_block:
                            if curr_block in block_match:
                                del block_match[curr_block]
                                duplicates.append(curr_block)
                            elif curr_block not in duplicates:
                                block_match[curr_block] = new_block

                for curr_block, new_block in block_match.iteritems():
                    for curr_function, new_function in \
                            zip(curr_block.functions, new_block.functions):
                        functions = find_function(self._program, curr_function)
                        if len(functions) == 1:
                            if new_function not in renamed:
                                renamed.append(new_function)
                                if self._rename_functions(functions[0],
                                                          new_function):
                                    rename_count += 1

        print("Renamed {function_count} functions and applied metadata to {metadata_count} functions."
              .format(function_count=rename_count, metadata_count=metadata_applied_count))

        return rename_count

    def _find_match(self, signatures):
        """
        Find matches to signatures in the current program.

        :param signatures: Signatures to find in current program.
        :type signatures: RizzoSignatures

        :returns: Tuple of matched signatures: (formal, string, immediate, fuzzy)
        :rtype: tuple
        """
        formal_signatures = find_signature_matches(
            signatures.formal, self._signatures.formal, signatures.functions,
            self._signatures.functions, 'formal signatures')

        string_signatures = find_signature_matches(
            signatures.strings, self._signatures.strings, signatures.functions,
            self._signatures.functions, 'string signatures')

        immediate_signatures = find_signature_matches(
            signatures.immediates, self._signatures.immediates,
            signatures.functions, self._signatures.functions,
            'immediate signatures')

        fuzzy_signatures = find_signature_matches(
            signatures.fuzzy, self._signatures.fuzzy, signatures.functions,
            self._signatures.functions, 'fuzzy signatures',
            lambda x, y: len(x.blocks) == len(y.blocks))

        return (formal_signatures, string_signatures, immediate_signatures,
                fuzzy_signatures)

    def _rename_functions(self, function, name):
        """
        Rename a function if the function has not be renamed and new name
        is a valid new function name. Previous renamed are determined by 
        searching for 'FUN_' in the function.

        :param function: Function to be renamed.
        :type function: ghidra.program.model.listing.Function

        :param name: New name to give function.
        :type name: unicode

        :returns: True if function renamed, False for no rename.
        :rtype: bool
        """
        if not function or not name:
            return False

        if 'FUN_' in function.name and 'FUN_' not in name:
            if function:
                print("Renaming {old_function_name} to {new_function_name}"
                      .format(old_function_name=function.name, new_function_name=name))
                function.setName(name, SourceType.USER_DEFINED)
                return True
        elif 'FUN_' not in function.name and 'FUN_' not in name and \
                function.name != name:
            print("Found match with {old_function_name} to {new_function_name} but did not rename."
                  .format(old_function_name=function.name, new_function_name=name))
        return False

    def _signature_hash(self, value):
        """
        Simple hash function used to create a signature.

        :param value: Value to hash.
        :type value: variable

        :returns: Signature hash
        :rtype: int
        """
        return hash(str(value)) & 0xFFFFFFFF

    def _find_strings(self):
        """
        Find strings in the current program and create signatures for them.
        """
        memory = self._memory_map.getAllInitializedAddressSet()
        strings = self._flat_api.findStrings(memory, 2, 1, True, True)

        for string in strings:
            addr = string.getAddress()
            value = string.getString(self._memory_map)
            xref = self._flat_api.getReferencesTo(addr)
            self._strings[addr.hashCode()] = RizzoString(addr, value, xref)

    def _get_function_blocks(self, function):
        """
        Get all code blocks in the provided function.

        :param function: Function to get code blocks from.
        :type function: ghidra.program.model.listing.Function

        :returns: List of code blocks.
        :rtype: ghidra.program.model.block.CodeBlock
        """
        blocks = []
        code_blocks = self._simple_blk.getCodeBlocksContaining(function.body,
                                                               self._monitor)

        while code_blocks.hasNext():
            blocks.append(code_blocks.next())

        return blocks

    def _hash_block(self, block):
        """
        Create signatures for the provided code block.

        :returns: Tuple of formal, fuzzy, function, and immediate signatures)
        """
        formal = []
        fuzzy = []
        functions = []
        immediates = []

        min_addr = block.minAddress
        max_addr = block.maxAddress

        curr_ins = self._flat_api.getInstructionAt(min_addr)

        while curr_ins and curr_ins.getAddress() < max_addr:
            code_ref = []
            data_ref = []

            # Create code and data reference signatures.
            references = curr_ins.getReferencesFrom()
            for reference in references:
                # Don't care about tracking stack references.
                if reference.isStackReference():
                    continue

                if is_code_ref(reference):
                    code_ref.append(reference)

                # Get data reads only if they are to valid memory.
                elif is_data_ref(reference) and \
                        self._memory_map.contains(reference.toAddress):
                    data_ref.append(reference)

            # Append the mnemonic string to the formal signature.
            formal.append(curr_ins.getMnemonicString())

            # If its a call instruction add the function call to the functions
            # signature and make note of the call in the fuzzy signature.
            if is_call_instruction(curr_ins):
                for cref in code_ref:
                    func = self._flat_api.getFunctionAt(cref.toAddress)
                    if func:
                        functions.append(func.getName())
                        fuzzy.append('funcref')
            # Make not of any data references.
            elif data_ref:
                for dref in data_ref:
                    addr_hash = dref.toAddress.hashCode()

                    if self._strings.has_key(addr_hash):
                        string_value = self._strings[addr_hash].value
                    else:
                        string_value = 'dataref'

                    formal.append(string_value)
                    fuzzy.append(string_value)
            # If not data or code then add everything to the formal signature.
            elif not data_ref and not code_ref:
                for i in range(0, curr_ins.getNumOperands()):
                    operand = curr_ins.getDefaultOperandRepresentation(i)
                    formal.append(operand)

                    op_type = curr_ins.getOperandRefType(i)
                    if op_type and op_type.isData():
                        # Indeterminate return values. Just put a try/except
                        # around it so the getValue AttributeError can be
                        # ignored. Not worth checking for types since those
                        # may come and go.
                        try:
                            op_value = curr_ins.getOpObjects(i)[0].getValue()
                            if op_value > 0xFFFF:
                                fuzzy.append(str(op_value))
                                immediates.append(op_value)
                        except (AttributeError, IndexError):
                            pass

            curr_ins = curr_ins.getNext()

        formal_sig = self._signature_hash(''.join(formal))
        fuzzy_sig = self._signature_hash(''.join(fuzzy))

        return (formal_sig, fuzzy_sig, immediates, functions)

    def _hash_function(self, function):
        """
        Create a block by block signature for the provided function.

        :param function: Function to create signature hash for.
        :type function: ghidra.program.model.listing.Function

        :returns: List of signatures per block found.
        """
        block_hash = []

        func_blocks = self._get_function_blocks(function)
        for block in func_blocks:
            block_hash.append(self._hash_block(block))

        return block_hash

    def _generate(self):
        """
        Create signatures for the current program.
        """
        signatures = RizzoSignature()

        # String based signatures
        string_count = 0
        total_strings = len(self._strings)
        print("Processing {} strings for signature generation...".format(total_strings))
        
        for (str_hash, curr_string) in self._strings.iteritems():
            # Only create signatures on reasonably long strings with one ref.
            if len(curr_string.value) >= 8 and len(curr_string.xrefs) == 1:
                function = self._flat_api.getFunctionContaining(
                    curr_string.xrefs[0].fromAddress)
                if function:
                    string_hash = self._signature_hash(curr_string.value)
                    entry = address_to_int(function.getEntryPoint())
                    signatures.add_string(string_hash, entry)
            
            string_count += 1
            if string_count % 100 == 0 or string_count == total_strings:
                print("  Processed {}/{} strings".format(string_count, total_strings))

        # Formal, fuzzy, and immediate-based function signatures
        all_functions = list(self._function_manager.getFunctions(True))
        total_functions = len(all_functions)
        function_count = 0
        
        print("Processing {} functions for signature generation...".format(total_functions))
        
        for function in all_functions:
            hashed_function_blocks = self._hash_function(function)

            formal = self._signature_hash(
                ''.join([str(e) for (e, _, _, _) in hashed_function_blocks]))
            fuzzy = self._signature_hash(
                ''.join([str(f) for (_, f, _, _) in hashed_function_blocks]))
            immediate = [str(i) for (_, _, i, _) in hashed_function_blocks]

            function_entry = address_to_int(function.getEntryPoint())
            
            # Extract enhanced function metadata using robust approaches
            function_signature = extract_function_signature(function)
            function_variables = extract_function_variables(function, self._program)  
            function_comments = extract_function_comments(function, self._program)
            
            # Store function data with enhanced metadata
            signatures.functions[function_entry] = (
                function.getName(),                           # [0] - name
                hashed_function_blocks,                      # [1] - blocks  
                function_signature,                          # [2] - signature info
                function_variables,                          # [3] - variables (comprehensive)
                function_comments.get('comment'),            # [4] - main comment
                function_comments.get('plate_comment'),      # [5] - plate comment
                function_comments.get('pre_comment'),        # [6] - pre comment
                function_comments.get('post_comment'),       # [7] - post comment
                function_comments.get('eol_comment'),        # [8] - EOL comment
                function_comments.get('repeatable_comment')  # [9] - repeatable comment
            )

            signatures.add_formal(formal, function_entry)
            signatures.add_fuzzy(fuzzy, function_entry)

            for value in immediate:
                signatures.add_immediate(value, function_entry)
            
            function_count += 1
            if function_count % 50 == 0 or function_count == total_functions:
                print("  Processed {}/{} functions ({:.1f}%)".format(
                    function_count, total_functions, 
                    (function_count * 100.0) / total_functions))

        print("Signature generation complete.")
        signatures.reset_dups()

        return signatures

    def load_signature_library(self, signature_library_file):
        """
        Load Rizzo signatures from a file into the library variable.

        :param signature_library_file: Full path to load signature library from.
        :type signature_library_file: str

        :returns: None
        :rtype: None
        """
        if not os.path.exists(signature_library_file):
            raise Exception("Signature file {signature_library_file} does not exist".format(signature_library_file=signature_library_file))

        print("Loading signature library from {signature_library_file}...".format(signature_library_file=signature_library_file))
        with open(signature_library_file, 'rb') as library_file:
            try:
                self.signature_libary = pickle.load(library_file)
            except:
                print("This does not appear to be a Rizzo signature file.")
                exit(1)
        print("done.")

    def add_current_program_to_library(self):
        formal_count_before_load = len(self.signature_libary.formal)
        fuzzy_count_before_load = len(self.signature_libary.fuzzy)
        strings_count_before_load = len(self.signature_libary.strings)
        functions_count_before_load = len(self.signature_libary.functions)
        immediates_count_before_load = len(self.signature_libary.immediates)
        formaldups_count_before_load = len(self.signature_libary.formaldups)
        fuzzydups_count_before_load = len(self.signature_libary.fuzzydups)
        stringdups_count_before_load = len(self.signature_libary.stringdups)
        functiondups_count_before_load = len(self.signature_libary.functiondups)
        immediatedups_count_before_load = len(self.signature_libary.immediatedups)

        for signature, address in self._signatures.formal.items():
            self.signature_libary.add_formal(signature, address)
        
        for signature, address in self._signatures.fuzzy.items():
            self.signature_libary.add_fuzzy(signature, address)

        for signature, address in self._signatures.strings.items():
            self.signature_libary.add_string(signature, address)

        for signature, address in self._signatures.functions.items():
            self.signature_libary.add_function(signature, address)

        for signature, address in self._signatures.immediates.items():
            self.signature_libary.add_immediate(signature, address)

        formal_count_after_load = len(self.signature_libary.formal)
        fuzzy_count_after_load = len(self.signature_libary.fuzzy)
        strings_count_after_load = len(self.signature_libary.strings)
        functions_count_after_load = len(self.signature_libary.functions)
        immediates_count_after_load = len(self.signature_libary.immediates)
        formaldups_count_after_load = len(self.signature_libary.formaldups)
        fuzzydups_count_after_load = len(self.signature_libary.fuzzydups)
        stringdups_count_after_load = len(self.signature_libary.stringdups)
        functiondups_count_after_load = len(self.signature_libary.functiondups)
        immediatedups_count_after_load = len(self.signature_libary.immediatedups)

        output_str = "Done! Library Change Statistics:\n" \
                     "\t\t\t\tOld\tNew\n" \
                     "Formal:\t\t{formal_before}\t{formal_after}\n" \
                     "Fuzzy:\t\t{fuzzy_before}\t{fuzzy_after}\n" \
                     "String:\t\t{string_before}\t{string_after}\n" \
                     "Function:\t{function_before}\t{function_after}\n" \
                     "Immediate:\t{immediate_before}\t{immediate_after}\n" \
                     "FormalDups:\t\t{formaldups_before}\t{formaldups_after}\n" \
                     "FuzzyDups:\t\t{fuzzydups_before}\t{fuzzydups_after}\n" \
                     "StringDups:\t\t{stringdups_before}\t{stringdups_after}\n" \
                     "FunctionDups:\t{functiondups_before}\t{functiondups_after}\n" \
                     "ImmediateDups:\t{immediatedups_before}\t{immediatedups_after}" \
                     .format(formal_before=formal_count_before_load,
                             formal_after=formal_count_after_load,
                             fuzzy_before=fuzzy_count_before_load,
                             fuzzy_after=fuzzy_count_after_load,
                             string_before=strings_count_before_load,
                             string_after=strings_count_after_load,
                             function_before=functions_count_before_load,
                             function_after=functions_count_after_load,
                             immediate_before=immediates_count_before_load,
                             immediate_after=immediates_count_after_load,
                             formaldups_before=formaldups_count_before_load,
                             formaldups_after=formaldups_count_after_load,
                             fuzzydups_before=fuzzydups_count_before_load,
                             fuzzydups_after=fuzzydups_count_after_load,
                             stringdups_before=stringdups_count_before_load,
                             stringdups_after=stringdups_count_after_load,
                             functiondups_before=functiondups_count_before_load,
                             functiondups_after=functiondups_count_after_load,
                             immediatedups_before=immediatedups_count_before_load,
                             immediatedups_after=immediatedups_count_after_load)

        print(output_str)
    
    def save_signature_library(self, signature_library_file):
        """
        Save Rizzo signature library to the supplied signature file.

        :param signature_file: Full path to save signatures.
        :type signature_file: str
        """
        print("Saving signature to {signature_library_file}...".format(signature_library_file=signature_library_file))
        with open(signature_library_file, 'wb') as library_file:
            pickle.dump(self.signature_libary, library_file)
        print("done.")
