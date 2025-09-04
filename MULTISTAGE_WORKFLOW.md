# Multi-Stage Rizzo Workflow Documentation

This document explains the two-stage approach to Rizzo signature generation and application, designed to capture both original function signatures AND manually analyzed function definitions.

## Overview

The multi-stage approach solves a key problem in firmware analysis: you want to match functions based on their original (unanalyzed) signatures, but apply the improved definitions that result from manual analysis.

### Traditional Workflow Problem
1. Load firmware → Generate signatures → Save signatures
2. Apply signatures to new firmware
3. **Problem**: If you manually improve the first firmware (rename functions, fix types, etc.) and re-generate signatures, the signatures themselves change, making them less effective for matching unanalyzed code in new firmware.

### Multi-Stage Solution
1. **Stage 1**: Generate signatures from unanalyzed firmware and store with original function definitions
2. **Manual Analysis**: Improve the firmware (rename functions, fix types, calling conventions, etc.)
3. **Stage 2**: Keep the original signatures but update function definitions with your improvements
4. **Application**: Match using original signatures, apply improved definitions

## Workflow Steps

### Step 1: Initial Signature Generation
**Script**: `RizzoStage1Save.py`

1. Load your firmware into Ghidra
2. Run the auto-analyzer 
3. Run `RizzoStage1Save.py`
4. Save the Stage 1 file (`.stage1` extension)

This captures:
- Function signatures based on the current (unanalyzed) state
- Original function definitions  
- Address mappings
- **Enhanced information**: Function signatures (return types, parameter types/names), local variables (names/types), function comments

### Step 2: Manual Analysis
Perform your manual analysis in Ghidra:
- Rename functions with meaningful names
- Fix function signatures and return types
- Update parameter types and names
- Set proper calling conventions
- Define local variables with proper names and types
- Add comments and documentation (plate, pre, post, eol, repeatable)

### Step 3: Capture Enhanced Definitions  
**Script**: `RizzoStage2Update.py`

1. Run `RizzoStage2Update.py`
2. Select your Stage 1 file as input
3. Save the final signature file (`.riz` extension)

This creates the final signature file containing:
- **Original signatures** (for matching against unanalyzed code)
- **Enhanced function definitions** (from your manual analysis)
  - Function names and signatures (return types, parameter types/names)
  - Local variable names and data types
  - All function comments (plate, pre, post, eol, repeatable)
  - Calling convention information

### Step 4: Apply to New Firmware
**Scripts**: `RizzoApplyEnhanced.py` or standard `RizzoApply.py`

1. Load new firmware into Ghidra
2. Run auto-analyzer
3. Apply the enhanced signature file

The matching process:
- Uses original signatures to identify functions in unanalyzed code
- Applies your improved function names and complete definitions
- Restores function signatures (return types, parameter types/names)
- Restores local variable names and types
- Restores all function comments and documentation
- Results in the new firmware having your complete enhanced analysis applied

## File Types

- **`.stage1`**: Stage 1 data containing original signatures and definitions
- **`.riz`**: Final signature file with original signatures + enhanced definitions
- **Standard `.riz`**: Traditional Rizzo signature files (still supported)

## Benefits

1. **Better Matching**: Original signatures match unanalyzed code more effectively
2. **Enhanced Application**: Apply your manual analysis improvements automatically
3. **Iterative Improvement**: Can re-run Stage 2 as you continue improving your analysis
4. **Backward Compatibility**: Enhanced signatures work with existing Rizzo apply scripts

## Advanced Usage

### Re-running Stage 2
You can run Stage 2 multiple times as you continue your manual analysis:
1. Continue improving your firmware analysis in Ghidra
2. Re-run `RizzoStage2Update.py` with the same Stage 1 file
3. Generate updated signature file with your latest improvements

### Combining Multiple Analyses
For comprehensive signature libraries, you can:
1. Run the two-stage process on multiple firmware versions
2. Use `RizzoLibraryCreation.py` to combine signature files
3. Build comprehensive libraries with enhanced definitions from multiple sources

## Example Scenario

1. **Load Original Firmware**: ESP32 firmware loaded into Ghidra
2. **Stage 1**: Generate signatures - function at 0x40080100 has signature `0xABCD1234` and name `FUN_40080100`
3. **Manual Analysis**: Determine function is actually `wifi_init()`, fix parameters, return type
4. **Stage 2**: Keep signature `0xABCD1234` but update definition to `wifi_init()`
5. **Apply to New Firmware**: 
   - Function at 0x40081200 matches signature `0xABCD1234`
   - Gets renamed from `FUN_40081200` to `wifi_init()`
   - Gets the improved function signature you defined

This approach ensures your manual analysis work benefits all future firmware analysis while maintaining effective signature matching.

## Troubleshooting

### Common Issues

**Functions not found in Stage 2**: 
- Functions may have been deleted or moved during manual analysis
- Stage 2 will keep original definitions for missing functions
- Check Ghidra's function list if you expect a function to be updated

**Signature mismatches when applying**:
- Ensure you're applying signatures to similar firmware versions
- Different compiler versions may produce different instruction patterns
- Consider using fuzzy matching for better results

**Performance considerations**:
- Large signature files may take time to process
- Consider breaking down very large analyses into smaller chunks
- Monitor memory usage with very large firmware images
