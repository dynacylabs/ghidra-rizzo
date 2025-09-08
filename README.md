# ghidra_rizzo
Rizzo for ghidra, with some touches from myself to make it more fault tolerant.

## Multi-Stage Signature System

This repository now includes an enhanced multi-stage signature system that solves the problem of manual analysis affecting signature matching. The issue was that after manual analysis (renaming functions, setting types, etc.), the function signatures would change and no longer match unanalyzed firmware.

### The Problem

1. Load program in Ghidra and analyze it
2. Perform manual analysis: rename functions, set parameter types, add comments, etc.
3. Run RizzoSave.py to save signatures
4. Try to apply signatures to unanalyzed firmware
5. **Signatures don't match** because they've been modified by manual analysis

### The Solution: Multi-Stage Workflow

The new system separates original signatures (for matching) from enhanced definitions (for restoration):

#### Stage 0: Save Original Signatures
- **Script**: `RizzoSaveOriginal.py`
- **When**: Run BEFORE any manual analysis
- **Purpose**: Captures unanalyzed function signatures and basic function info
- **Output**: `.riz0` file containing original signatures and function mappings

#### Manual Analysis Phase
Perform your manual analysis as usual:
- Rename functions with meaningful names
- Set proper parameter types and names  
- Set return types
- Add function comments
- Rename local variables
- Set variable data types

#### Stage 1: Save Enhanced Definitions
- **Script**: `RizzoSaveEnhanced.py`
- **When**: Run AFTER manual analysis is complete
- **Purpose**: Links enhanced function definitions to original signatures
- **Input**: Requires the `.riz0` file from Stage 0
- **Output**: `.riz1` file containing both original signatures and enhanced definitions

#### Apply Enhanced Signatures
- **Script**: `RizzoApplyEnhanced.py`
- **When**: Apply to target programs
- **How it works**:
  1. Uses original signatures for function matching (high accuracy)
  2. Once matches are found, applies enhanced definitions to target functions
  3. Restores: function names, parameter types/names, return types, comments, variable names/types

### File Types

- **`.riz0`**: Stage 0 files containing original signatures
- **`.riz1`**: Stage 1 files containing original signatures + enhanced definitions  
- **`.riz`**: Legacy single-stage signature files (still supported)

### Workflow Helper

Use `RizzoWorkflowHelper.py` to:
- Check your current workflow status
- See what signature files exist
- Get recommendations for next steps
- View program analysis progress

### Benefits

1. **High matching accuracy**: Uses unmodified original signatures
2. **Rich restoration**: Applies full manual analysis results  
3. **Version tracking**: Tracks which functions were manually analyzed
4. **Backward compatibility**: Still works with legacy `.riz` files
5. **Better organization**: Clear workflow stages

### Usage Example

```
1. Load firmware in Ghidra, run auto-analysis
2. Run RizzoSaveOriginal.py → creates firmware.riz0
3. Perform manual analysis (rename, retype, comment functions)
4. Run RizzoSaveEnhanced.py → creates firmware.riz1  
5. Load target firmware in Ghidra
6. Run RizzoApplyEnhanced.py with firmware.riz1
7. Original signatures match functions, enhanced definitions are applied
```

## Legacy Scripts

The original Rizzo scripts are still included and fully functional:
- `rizzo.py` - Core Rizzo functionality
- `RizzoSave.py` - Save legacy signatures
- `RizzoApply.py` - Apply legacy signatures  
- `RizzoApplyRecursive.py` - Recursive application
- Other utility scripts

## Requirements

- Ghidra
- Python (for Ghidra scripting)
- The scripts assume custom data types are already present (transferred separately)
