# @runtime PyGhidra

# Stage 0: Save original function signatures before manual analysis
# @author fuzzywalls
# @category TNS
# @menupath TNS.Rizzo.Save Original Signatures (Stage 0)

import rizzo
import pickle
import time
from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface

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
    
    # Set up decompiler for accessing high-level function information
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    
    # Create enhanced signature data structure that includes original function info
    original_signatures = {
        'rizzo_signatures': rizz._signatures,  # Standard Rizzo signatures for matching
        'original_functions': {},  # Map address -> original function info
        'timestamp': time.time(),
        'program_name': currentProgram.getName()
    }
    
    # Capture original function information for each function
    function_manager = currentProgram.getFunctionManager()
    
    total_functions = function_manager.getFunctionCount()
    current_function = 0
    
    for function in function_manager.getFunctions(True):
        current_function += 1
        if current_function % 50 == 0:
            print(f"Processing function {current_function}/{total_functions}: {function.getName()}")
            
        address = int(function.getEntryPoint().toString(), 16)
        
        # Store original function information
        original_signatures['original_functions'][address] = {
            'name': function.getName(),
            'signature': get_function_signature_string(function),
            'parameters': get_function_parameters(function),
            'return_type': str(function.getReturnType()) if function.getReturnType() else 'void',
            'comment': get_function_comment(function),
            'local_variables': get_function_variables_high_level(function, decompiler)
        }
    
    decompiler.dispose()
    
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

def get_function_variables_high_level(function, decompiler):
    """Extract local variable information using high-level function representation."""
    variables = []
    
    try:
        # Get high-level function representation
        decompiler_results = decompiler.decompileFunction(function, 30, None)
        if decompiler_results and decompiler_results.decompileCompleted():
            high_func = decompiler_results.getHighFunction()
            if high_func:
                local_symbols = high_func.getLocalSymbolMap().getSymbols()
                for symbol in local_symbols:
                    # Skip parameters since they're handled separately
                    if symbol.isParameter():
                        continue
                        
                    variables.append({
                        'name': symbol.getName(),
                        'type': str(symbol.getDataType()),
                        'category': 'local',
                        'is_parameter': symbol.isParameter(),
                        'storage': str(symbol.getStorage()) if hasattr(symbol, 'getStorage') else ""
                    })
                    
        # Fallback: if high-level decompilation fails, try basic variable extraction
        if not variables:
            try:
                for var in function.getLocalVariables():
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
        print(f"Warning: Could not extract high-level variables for {function.getName()}: {e}")
        
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

# Run the stage 0 process
save_original_signatures()
