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





# Export Workflow
1. Load source program into Ghidra (Referred to as `<source_program>`)
2. Run Ghidra's Analyzer
3. Run `periph_enum.py`
4. Re-run Ghidra's Analyzer
5. Run `mem_export.py` (Save as `<source_program>.mem`)
6. Run `rizzo_stage0.py` (Save as `<source_program>.riz0`)
7. Run `ai_auto_analysis.py`
8. Re-run Ghidra's Analyzer
9. Run `rizzo_stage1.py` (Save as `<source_program>.riz1`)
10. In Ghidra's Data Type Manager:
- Create a "New File Archive" (Save as `<source_program>.gdt`)
- Under the `<source_program>` archive, drag `AI_Generated_Structs` to the new `<source_program>.gdt` archive
  - Answer "Yes" to "Do you want to associate local data types with the target archive?"
- "Commit Data Types To" and select the new `<source_program>.gdt` archive
- Close the new `<source_program>.gdt` archive

# Import Workflow
1. Load the target program into Ghidra (Referred to as `<target_program>`)
2. Run Ghidra's Analyzer
3. Run `mem_import.py` (Select `<source_program>.mem`)
4. Re-run Ghidra's Analyzer
5. Run `periph_enum.py` (Enumerates new peripherals)
6. Re-run Ghidra's Analyzer
7. In Ghidra's Data Type Manager, "Open File Archive" and load `<source_program>.gdt`
8. Run `rizzo_apply.py` and load `<source_program>.riz1`
9. Re-run Ghidra's Analyzer