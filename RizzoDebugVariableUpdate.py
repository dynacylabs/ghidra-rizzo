# Debug script for testing variable updates on current function
# @author fuzzywalls
# @category TNS
# @menupath TNS.Rizzo.Debug Variable Update

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType

def debug_variable_update():
    """
    Debug variable update process on the current function.
    """
    
    # Get current function
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
    
    print(f"Testing variable updates for function: {function.getName()}")
    print("=" * 60)
    
    # Set up decompiler and utilities
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    high_func_db_util = HighFunctionDBUtil()
    
    try:
        # Get high-level function representation
        decompiler_results = decompiler.decompileFunction(function, 30, None)
        if not decompiler_results or not decompiler_results.decompileCompleted():
            print("Could not decompile function")
            return
            
        high_func = decompiler_results.getHighFunction()
        if not high_func:
            print("Could not get high-level function")
            return
            
        local_symbols = high_func.getLocalSymbolMap().getSymbols()
        
        # Show current variables
        print("CURRENT VARIABLES:")
        variables = []
        for i, symbol in enumerate(local_symbols):
            if not symbol.isParameter():
                variables.append(symbol)
                storage = ""
                try:
                    storage = str(symbol.getStorage())
                except:
                    storage = "N/A"
                    
                print(f"  {len(variables)}. {symbol.getName()} : {symbol.getDataType()}")
                print(f"      Storage: {storage}")
                print(f"      Symbol type: {type(symbol)}")
                print(f"      Has setName: {hasattr(symbol, 'setName')}")
                if hasattr(symbol, 'getVariable'):
                    var = symbol.getVariable()
                    print(f"      Has variable: {var is not None}")
                    if var:
                        print(f"      Variable type: {type(var)}")
                        print(f"      Variable has setName: {hasattr(var, 'setName')}")
                        print(f"      Variable has setDataType: {hasattr(var, 'setDataType')}")
        
        print("")
        
        if not variables:
            print("No local variables found")
            return
            
        # Test updating the first variable
        test_symbol = variables[0]
        old_name = test_symbol.getName()
        new_name = f"{old_name}_RENAMED"
        
        print(f"TESTING UPDATE: {old_name} -> {new_name}")
        print("-" * 40)
        
        # Method 1: updateDBVariable
        print("Method 1: updateDBVariable")
        try:
            high_func_db_util.updateDBVariable(
                test_symbol, new_name, test_symbol.getDataType(), SourceType.USER_DEFINED
            )
            
            high_func_db_util.commitParamsToDatabase(
                high_func,
                True,
                HighFunctionDBUtil.ReturnCommitOption.COMMIT,
                SourceType.USER_DEFINED,
            )
            
            # Check if it worked
            updated_name = test_symbol.getName()
            print(f"  Result: {old_name} -> {updated_name}")
            print(f"  Success: {updated_name == new_name}")
            
        except Exception as e:
            print(f"  Failed: {e}")
            
        print("")
        
        # Method 2: Direct symbol setName (if available)
        if hasattr(test_symbol, 'setName'):
            print("Method 2: symbol.setName")
            try:
                test_name2 = f"{old_name}_DIRECT"
                test_symbol.setName(test_name2, SourceType.USER_DEFINED)
                updated_name2 = test_symbol.getName()
                print(f"  Result: {old_name} -> {updated_name2}")
                print(f"  Success: {updated_name2 == test_name2}")
            except Exception as e:
                print(f"  Failed: {e}")
        else:
            print("Method 2: symbol.setName - Not available")
            
        print("")
        
        # Method 3: Variable setName (if available)
        if hasattr(test_symbol, 'getVariable'):
            var = test_symbol.getVariable()
            if var and hasattr(var, 'setName'):
                print("Method 3: variable.setName")
                try:
                    test_name3 = f"{old_name}_VARIABLE"
                    var.setName(test_name3, SourceType.USER_DEFINED)
                    updated_name3 = test_symbol.getName()
                    print(f"  Result: {old_name} -> {updated_name3}")
                    print(f"  Success: {updated_name3 == test_name3}")
                except Exception as e:
                    print(f"  Failed: {e}")
            else:
                print("Method 3: variable.setName - Not available")
        else:
            print("Method 3: variable.setName - No getVariable method")
            
    finally:
        decompiler.dispose()
    
    print("")
    print("=" * 60)
    print("Debug test complete")

# Run the debug test
debug_variable_update()
