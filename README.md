# ghidra_rizzo
Rizzo for Ghidra, with enhancements for multi-stage signature generation and fault tolerance.

## Overview

Rizzo is a function signature matching tool for binary analysis in Ghidra. This enhanced version adds a multi-stage workflow that preserves original signatures while capturing manual analysis improvements.

## Features

- **Multi-Stage Workflow**: Generate signatures from unanalyzed code, perform manual analysis, then capture enhanced definitions while preserving original signatures
- **Enhanced Fault Tolerance**: Improved error handling and recovery
- **Backward Compatibility**: Works with existing Rizzo signature files
- **Library Management**: Build and manage signature libraries across multiple firmware images

## Quick Start

### Traditional Workflow
1. `RizzoSave.py` - Generate signatures from current program
2. `RizzoApply.py` - Apply signatures to new program

### Multi-Stage Workflow (Recommended)
1. `RizzoStage1Save.py` - Generate initial signatures (before manual analysis)
2. Perform manual analysis in Ghidra (rename functions, fix types, etc.)
3. `RizzoStage2Update.py` - Capture enhanced definitions with original signatures
4. `RizzoApplyEnhanced.py` - Apply enhanced signatures to new programs

## Scripts

### Core Scripts
- **RizzoSave.py** - Save signatures from current program
- **RizzoApply.py** - Apply signatures to current program
- **RizzoStage1Save.py** - Stage 1: Save initial signatures and definitions
- **RizzoStage2Update.py** - Stage 2: Update definitions with manual analysis
- **RizzoApplyEnhanced.py** - Apply enhanced multi-stage signatures

### Library Management
- **RizzoLibraryCreation.py** - Create signature libraries
- **RizzoApplyMulti.py** - Apply multiple signature files
- **RizzoApplyRecursive.py** - Recursively apply signatures

### Utilities  
- **RizzoValidateSignatures.py** - Validate and inspect signature files
- **esp-idf_RizzoApplyRecursive.py** - ESP-IDF specific recursive application

## Documentation

See `MULTISTAGE_WORKFLOW.md` for detailed documentation on the multi-stage approach, including:
- Step-by-step workflow
- Benefits and use cases
- Troubleshooting guide
- Advanced usage scenarios

## Multi-Stage Benefits

1. **Better Matching**: Original signatures match unanalyzed code more effectively than signatures from heavily analyzed code
2. **Preserve Analysis**: Your manual analysis work (function names, types, signatures) gets applied automatically to new firmware
3. **Iterative Improvement**: Can re-run Stage 2 as you continue improving your analysis
4. **Scalable**: Build comprehensive libraries from multiple analyzed firmware images

## Example Use Case

Analyzing ESP32 firmware variants:
1. Load first firmware variant, run Stage 1
2. Manually analyze and improve function definitions  
3. Run Stage 2 to capture improvements
4. Apply enhanced signatures to other firmware variants
5. All variants now benefit from your analysis of the first one

## Requirements

- Ghidra (tested with recent versions)
- Python 2.7 (Ghidra's embedded Jython)

## Installation

1. Copy all `.py` files to your Ghidra scripts directory
2. Refresh the script manager in Ghidra
3. Scripts will appear under `TNS > Rizzo` in the menu

## File Extensions

- `.stage1` - Stage 1 signature files (original signatures + definitions)
- `.riz` - Final signature files (original signatures + enhanced definitions)
