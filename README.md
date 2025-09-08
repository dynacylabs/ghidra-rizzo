# ghidra_rizzo
Rizzo for ghidra, with some touches from myself to make it more fault tolerant.

# Steps
1. Load source program into Ghidra
2. Run Ghidra's analyzer on source program
3. Run `rizzo_stage0.py` (will save a `.riz0` file)
4. Perform manual analysis
5. Run `rizzo_stage1.py` (will save a `.riz1` file)
6. Load target program into Ghidra
7. Run Ghidra's analyzer on target program
8. Run `rizzo_apply.py` (select `.riz1` file)
