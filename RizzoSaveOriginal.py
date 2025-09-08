# @runtime PyGhidra

# Stage 0: Save original function signatures before manual analysis
# @author fuzzywalls
# @category TNS
# @menupath TNS.Rizzo.Save Original Signatures (Stage 0)

import rizzo
import pickle
import time
from ghidra.program.model.symbol import SourceType

def save_original_signatures():
    """
    Save original function signatures with addresses for later mapping to enhanced definitions.
    This should be run BEFORE manual analysis to capture the unanalyzed function signatures.
    """
    
    file_path = askFile('Save original signature file as', 'OK').path
    if not file_path.endswith('.riz0'):
        file_path += '.riz0'
    
    print('Building original Rizzo signatures (Stage 0), this may take a few minutes...')
    
    # Create standard Rizzo signatures for matching purposes
    rizz = rizzo.Rizzo(currentProgram)
    
    # Create enhanced signature data structure that includes original function info
    original_signatures = {
        'rizzo_signatures': rizz._signatures,  # Standard Rizzo signatures for matching
        'original_functions': {},  # Map address -> original function info
        'timestamp': time.time(),
        'program_name': currentProgram.getName()
    }
    
    # Capture original function information for each function
    function_manager = currentProgram.getFunctionManager()
    
    for function in function_manager.getFunctions(True):
        address = int(function.getEntryPoint().toString(), 16)
        
        # Store original function information
        original_signatures['original_functions'][address] = {
            'name': function.getName(),
            'signature': get_function_signature_string(function),
            'parameters': get_function_parameters(function),
            'return_type': str(function.getReturnType()) if function.getReturnType() else 'void',
            'comment': get_function_comment(function),
            'local_variables': get_function_variables(function)
        }
    
    print(f"Saving original signatures for {len(original_signatures['original_functions'])} functions to {file_path}...")
    
    with open(file_path, 'wb') as f:
        pickle.dump(original_signatures, f)
    
    print("Stage 0 complete. Original signatures saved.")
    print(f"Functions captured: {len(original_signatures['original_functions'])}")

def get_function_signature_string(function):
    """Get a string representation of the function signature."""
    try:
        return function.getSignature().getPrototypeString()
    except:
        return f"{function.getReturnType() or 'void'} {function.getName()}()"

def get_function_parameters(function):
    """Extract function parameter information."""
    params = []
    for param in function.getParameters():
        params.append({
            'name': param.getName(),
            'type': str(param.getDataType()),
            'comment': param.getComment() or ""
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

def get_function_variables(function):
    """Extract local variable information."""
    variables = []
    try:
        for var in function.getLocalVariables():
            variables.append({
                'name': var.getName(),
                'type': str(var.getDataType()),
                'comment': var.getComment() or ""
            })
    except:
        pass
    return variables

# Run the stage 0 process
save_original_signatures()
