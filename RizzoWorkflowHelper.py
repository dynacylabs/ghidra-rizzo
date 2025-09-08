# Utility script for multi-stage Rizzo workflow management
# @author fuzzywalls
# @category TNS
# @menupath TNS.Rizzo.Multi-Stage Workflow Helper

import os
import pickle
from datetime import datetime

def workflow_helper():
    """
    Interactive helper for the multi-stage Rizzo workflow.
    Provides information and guidance for the multi-stage process.
    """
    
    print("=" * 70)
    print("RIZZO MULTI-STAGE WORKFLOW HELPER")
    print("=" * 70)
    print("")
    print("This helper guides you through the multi-stage signature process:")
    print("")
    print("STAGE 0: Save Original Signatures (RizzoSaveOriginal.py)")
    print("  - Run BEFORE manual analysis")
    print("  - Captures unanalyzed function signatures")
    print("  - Creates .riz0 file")
    print("")
    print("MANUAL ANALYSIS:")
    print("  - Rename functions")
    print("  - Set parameter types and names")
    print("  - Set return types")
    print("  - Add function comments")
    print("  - Rename local variables")
    print("  - Set variable types")
    print("")
    print("STAGE 1: Save Enhanced Signatures (RizzoSaveEnhanced.py)")
    print("  - Run AFTER manual analysis")
    print("  - Links enhanced definitions to original signatures")
    print("  - Creates .riz1 file")
    print("")
    print("APPLY: Apply Enhanced Signatures (RizzoApplyEnhanced.py)")
    print("  - Use original signatures for matching")
    print("  - Apply enhanced definitions to target program")
    print("")
    
    # Check for existing signature files in the program directory
    program_path = currentProgram.getExecutablePath()
    program_dir = os.path.dirname(program_path) if program_path else None
    
    if program_dir:
        print("SIGNATURE FILES IN PROGRAM DIRECTORY:")
        print("-" * 40)
        
        riz0_files = []
        riz1_files = []
        riz_files = []
        
        try:
            for file in os.listdir(program_dir):
                if file.endswith('.riz0'):
                    riz0_files.append(file)
                elif file.endswith('.riz1'):
                    riz1_files.append(file)
                elif file.endswith('.riz'):
                    riz_files.append(file)
        except:
            print("Could not access program directory")
        
        if riz0_files:
            print("Stage 0 files (.riz0):")
            for file in riz0_files:
                print(f"  {file}")
                show_file_info(os.path.join(program_dir, file))
            print("")
        
        if riz1_files:
            print("Stage 1 files (.riz1):")
            for file in riz1_files:
                print(f"  {file}")
                show_file_info(os.path.join(program_dir, file))
            print("")
        
        if riz_files:
            print("Legacy Rizzo files (.riz):")
            for file in riz_files:
                print(f"  {file}")
            print("")
        
        if not (riz0_files or riz1_files or riz_files):
            print("No signature files found in program directory")
            print("")
    
    # Show current program analysis state
    print("CURRENT PROGRAM ANALYSIS STATE:")
    print("-" * 40)
    
    function_manager = currentProgram.getFunctionManager()
    functions = list(function_manager.getFunctions(True))
    
    default_names = 0
    custom_names = 0
    commented_functions = 0
    
    for function in functions:
        name = function.getName()
        
        # Check if function has default name (like FUN_...)
        if name.startswith('FUN_') or name.startswith('SUB_') or name.startswith('thunk_'):
            default_names += 1
        else:
            custom_names += 1
            
        # Check for comments
        try:
            code_unit = currentProgram.getListing().getCodeUnitAt(function.getEntryPoint())
            if code_unit and code_unit.getComment(code_unit.PLATE_COMMENT):
                commented_functions += 1
        except:
            pass
    
    total_functions = len(functions)
    print(f"Total functions: {total_functions}")
    print(f"Default names: {default_names}")
    print(f"Custom names: {custom_names}")
    print(f"Commented functions: {commented_functions}")
    
    analysis_percentage = (custom_names / total_functions * 100) if total_functions > 0 else 0
    print(f"Analysis progress: {analysis_percentage:.1f}%")
    print("")
    
    # Provide recommendations
    print("RECOMMENDATIONS:")
    print("-" * 40)
    
    if not riz0_files:
        print("• Run Stage 0 (RizzoSaveOriginal.py) to capture original signatures")
    elif custom_names > 0 and not riz1_files:
        print("• You have custom function names - consider running Stage 1 (RizzoSaveEnhanced.py)")
    elif riz1_files:
        print("• You have enhanced signatures ready for application")
        print("• Use RizzoApplyEnhanced.py to apply them to target programs")
    
    if analysis_percentage < 10:
        print("• Consider doing more manual analysis before Stage 1")
    
    print("")
    print("=" * 70)

def show_file_info(file_path):
    """Show information about a signature file."""
    try:
        with open(file_path, 'rb') as f:
            data = pickle.load(f)
        
        if 'timestamp' in data:
            timestamp = datetime.fromtimestamp(data['timestamp'])
            print(f"    Created: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if 'program_name' in data:
            print(f"    Program: {data['program_name']}")
        
        if 'original_functions' in data:
            print(f"    Original functions: {len(data['original_functions'])}")
            
        if 'enhanced_functions' in data:
            print(f"    Enhanced functions: {len(data['enhanced_functions'])}")
            manually_analyzed = sum(1 for f in data['enhanced_functions'].values() 
                                  if f.get('was_manually_analyzed', False))
            print(f"    Manually analyzed: {manually_analyzed}")
            
    except Exception as e:
        print(f"    Error reading file: {e}")

# Run the workflow helper
workflow_helper()
