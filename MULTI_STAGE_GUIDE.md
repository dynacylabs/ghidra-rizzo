# Multi-Stage Rizzo Quick Reference Guide

## Overview
The multi-stage Rizzo system solves the manual analysis signature mismatch problem by separating original signatures (for matching) from enhanced definitions (for restoration).

## File Extensions
- `.riz0` - Stage 0: Original signatures before manual analysis
- `.riz1` - Stage 1: Enhanced definitions linked to original signatures  
- `.riz`  - Legacy: Single-stage signatures (still supported)

## Workflow

### 1. Stage 0: Capture Original Signatures
**Script**: `RizzoSaveOriginal.py`
**Timing**: Before any manual analysis
```
Load firmware → Auto-analyze → Run RizzoSaveOriginal.py → firmware.riz0
```

### 2. Manual Analysis Phase
Perform manual analysis as usual:
- Rename functions with meaningful names
- Set parameter types and names
- Set return types  
- Add function comments
- Rename local variables
- Set variable data types

### 3. Stage 1: Save Enhanced Definitions
**Script**: `RizzoSaveEnhanced.py`
**Timing**: After manual analysis is complete
**Input**: Requires corresponding `.riz0` file
```
Manual analysis complete → Run RizzoSaveEnhanced.py → firmware.riz1
```

### 4. Apply Enhanced Signatures
**Script**: `RizzoApplyEnhanced.py`
**Input**: `.riz1` file
**Process**:
1. Uses original signatures to find function matches
2. Applies enhanced definitions to matched functions
3. Restores all manual analysis work

## What Gets Restored

### Function Level
- Function name
- Return type
- Function comments

### Parameters
- Parameter names
- Parameter types
- Parameter order

### Local Variables  
- Variable names
- Variable data types
- Variable categories

## Helper Tools

### Workflow Helper
**Script**: `RizzoWorkflowHelper.py`
- Shows current workflow status
- Lists existing signature files
- Provides next-step recommendations
- Shows analysis progress

## Best Practices

1. **Always run Stage 0 first** - Before any manual changes
2. **Keep .riz0 files safe** - They're needed for Stage 1
3. **Run Stage 1 when analysis is complete** - Don't run it mid-analysis
4. **Use descriptive filenames** - Include firmware version/variant
5. **Test on small programs first** - Validate the workflow

## Troubleshooting

### Common Issues

**"No enhanced signature file found"**
- Ensure you're selecting a `.riz1` file
- Check that Stage 1 was completed successfully

**"Original signature file not found"**  
- Verify the `.riz0` file exists
- Ensure it's in the expected location

**"Function matches but definition not applied"**
- Check that enhanced function exists in `.riz1` file
- Verify data types are available in target program

**"Type mapping errors"**
- Custom data types may need to be imported separately
- Check rizzo_type_utils.py for supported types

### File Compatibility

- `.riz1` files contain both original and enhanced data
- `.riz1` files are backward compatible for matching
- Legacy `.riz` files still work with standard apply scripts

## Data Structure

### .riz0 File Contents
```python
{
    'rizzo_signatures': RizzoSignature,  # Standard Rizzo signatures
    'original_functions': {              # Address -> function info
        address: {
            'name': str,
            'signature': str, 
            'parameters': list,
            'return_type': str,
            'comment': str,
            'local_variables': list
        }
    },
    'timestamp': float,
    'program_name': str
}
```

### .riz1 File Contents  
```python
{
    'rizzo_signatures': RizzoSignature,  # Original signatures (for matching)
    'original_functions': dict,          # From .riz0 file
    'enhanced_functions': {              # Address -> enhanced info
        address: {
            'name': str,
            'signature': str,
            'parameters': list,
            'return_type': str, 
            'comment': str,
            'local_variables': list,
            'decompiled_code': str,
            'was_manually_analyzed': bool
        }
    },
    'timestamp': float,
    'program_name': str,
    'original_timestamp': float
}
```

## Migration from Legacy

Existing `.riz` files continue to work with:
- `RizzoApply.py`
- `RizzoApplyRecursive.py`  
- `RizzoApplyMulti.py`

To migrate to multi-stage:
1. Use legacy `.riz` with `RizzoApplyEnhanced.py` (limited functionality)
2. Or restart with Stage 0 → Manual Analysis → Stage 1 workflow
