# Variable extraction test script for debugging Rizzo multi-stage system
# @author fuzzywalls
# @category TNS
# @menupath TNS.Rizzo.Test Variable Extraction

from ghidra.app.decompiler import DecompInterface

def test_variable_extraction():
    """
    Test variable extraction on the current function to debug issues.
    """
    
    # Get current function (where cursor is positioned)
    current_location = currentLocation
    if not current_location:
        print("No current location. Please position cursor in a function.")
        return
        
    current_address = current_location.getAddress()
    function_manager = currentProgram.getFunctionManager()
    function = function_manager.getFunctionContaining(current_address)
    
    if not function:
        print("No function found at current location.")
        return
    
    print(f"Testing variable extraction for function: {function.getName()}")
    print(f"Function address: {function.getEntryPoint()}")
    print("=" * 60)
    
    # Set up decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    
    try:
        # Test basic variable extraction
        print("1. BASIC VARIABLE EXTRACTION:")
        print("-" * 30)
        try:
            basic_vars = function.getLocalVariables()
            print(f"Found {len(basic_vars)} variables using getLocalVariables()")
            for i, var in enumerate(basic_vars):
                print(f"  {i+1}. {var.getName()} : {var.getDataType()}")
                if hasattr(var, 'getVariableStorage'):
                    print(f"      Storage: {var.getVariableStorage()}")
        except Exception as e:
            print(f"Basic variable extraction failed: {e}")
        
        print("")
        
        # Test high-level variable extraction
        print("2. HIGH-LEVEL VARIABLE EXTRACTION:")
        print("-" * 35)
        try:
            decompiler_results = decompiler.decompileFunction(function, 30, None)
            if decompiler_results and decompiler_results.decompileCompleted():
                print("Decompilation successful")
                high_func = decompiler_results.getHighFunction()
                if high_func:
                    print("High-level function obtained")
                    local_symbols = high_func.getLocalSymbolMap().getSymbols()
                    
                    param_count = 0
                    local_count = 0
                    
                    print(f"Found {len(local_symbols)} total symbols")
                    for i, symbol in enumerate(local_symbols):
                        is_param = symbol.isParameter()
                        if is_param:
                            param_count += 1
                        else:
                            local_count += 1
                            
                        symbol_type = "PARAM" if is_param else "LOCAL"
                        storage = ""
                        try:
                            storage = str(symbol.getStorage())
                        except:
                            storage = "N/A"
                            
                        print(f"  {i+1}. [{symbol_type}] {symbol.getName()} : {symbol.getDataType()}")
                        print(f"      Storage: {storage}")
                        
                    print(f"\nSummary: {param_count} parameters, {local_count} local variables")
                else:
                    print("Failed to get high-level function")
            else:
                print("Decompilation failed")
                if decompiler_results:
                    print(f"Error: {decompiler_results.getErrorMessage()}")
                    
        except Exception as e:
            print(f"High-level variable extraction failed: {e}")
        
        print("")
        
        # Test decompiled code extraction
        print("3. DECOMPILED CODE:")
        print("-" * 18)
        try:
            decompiler_results = decompiler.decompileFunction(function, 30, None)
            if decompiler_results and decompiler_results.decompileCompleted():
                c_code = decompiler_results.getDecompiledFunction().getC()
                lines = c_code.split('\n')
                print(f"Decompiled code ({len(lines)} lines):")
                
                # Show first 20 lines
                for i, line in enumerate(lines[:20]):
                    print(f"  {i+1:2d}: {line}")
                    
                if len(lines) > 20:
                    print(f"  ... ({len(lines) - 20} more lines)")
            else:
                print("Decompilation failed for code extraction")
        except Exception as e:
            print(f"Decompiled code extraction failed: {e}")
            
    finally:
        decompiler.dispose()
    
    print("")
    print("=" * 60)
    print("Variable extraction test complete")

# Run the test
test_variable_extraction()
