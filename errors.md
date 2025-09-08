     65. secondary_base_pointer : uint * (storage: Stack[-0x30]:4)
      66. secondary_offset : int (storage: Stack[-0x2c]:4)
      67. peripheral_controller_pointer : int * (storage: Stack[-0x28]:4)
      68. primary_base : int (storage: Stack[-0x20]:4)
      69. secondary_base : int (storage: Stack[-0x1c]:4)
      70. bVar24 : bool (storage: tmpZR:1)
      71. cVar25 : char (storage: tmpCY:1)
      72. uVar26 : undefined8 (storage: r1:4,r0:4)
      73. puVar20 : uint * (storage: r3:4)
      74. pcVar21 : char * (storage: r3:4)
      75. uVar22 : undefined1 (storage: r6:1)
      76. iVar23 : int (storage: r7:4)
    → Strategy 1: Matching by storage location...
    Renaming variable: puStack_18 -> temp_config_data
    → Attempting direct function variable approach...
    ✗ Direct variable update approach failed: 'ghidra.program.database.function.ParameterDB' object has no attribute 'isParameter'
    → Trying decompiler approach as fallback...
    ✓ Decompiler name update reported success
    → Neither old nor expected variable found (variable may have been modified)
    ⚠ Verification failed: Changes may not have persisted
    ✓ Storage match: puStack_18 -> temp_config_data
    Updating variable: uVar11 (uint) -> iVar8 (int)
    → Attempting direct function variable approach...
    ✗ Direct variable update approach failed: 'ghidra.program.database.function.ParameterDB' object has no attribute 'isParameter'
    → Trying decompiler approach as fallback...
    ✓ Decompiler combined update reported success
    → Old variable still exists: uVar11 : int
    → Expected variable not found, old variable still exists
    ⚠ Verification failed: Changes may not have persisted
    ✓ Storage match: uVar11 -> iVar8
    Updating variable: uVar12 (undefined4) -> input_data_3 (uint *)
    → Attempting direct function variable approach...
    ✗ Direct variable update approach failed: 'ghidra.program.database.function.ParameterDB' object has no attribute 'isParameter'
    → Trying decompiler approach as fallback...
    ✓ Decompiler combined update reported success
