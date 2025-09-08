d0' ≠ 'inner_loop_counter'), Type ✗ ('undefined8[8]' ≠ 'int')
    Updating variable: local_474 (undefined2[530]) -> temporary_stack_pointer (int *)
    ✓ Combined update successful: temporary_stack_pointer : int *
    ✗ Verification failed: Name ✗ ('local_474' ≠ 'temporary_stack_pointer'), Type ✗ ('undefined2[530]' ≠ 'int *')
    Updating variable: local_50 (undefined1[12]) -> config_byte_b (int)
    ✓ Combined update successful: config_byte_b : int
    ✗ Verification failed: Name ✗ ('local_50' ≠ 'config_byte_b'), Type ✗ ('undefined1[12]' ≠ 'int')
    Updating variable: local_44 (uint) -> temporary_buffer_current_section (uint *)
    ✓ Combined update successful: temporary_buffer_current_section : uint *
    ✗ Verification failed: Name ✗ ('local_44' ≠ 'temporary_buffer_current_section'), Type ✗ ('uint' ≠ 'uint *')
    Renaming variable: local_40 -> normalized_value
    ✓ Name update successful: normalized_value
    ✗ Verification failed: Name ✗ ('local_40' ≠ 'normalized_value')
    Updating variable: local_3c (uint) -> current_memory_section (uint *)
    ✓ Combined update successful: current_memory_section : uint *
    ✗ Verification failed: Name ✗ ('local_3c' ≠ 'current_memory_section'), Type ✗ ('uint' ≠ 'uint *')
    Renaming variable: iVar4 -> loop_counter
    ✓ Name update successful: loop_counter
    ✗ Verification failed: Name ✗ ('iVar4' ≠ 'loop_counter')
    Updating variable: local_38 (undefined2) -> extra_return_value2 (uint)
    ✓ Combined update successful: extra_return_value2 : uint
    ✗ Verification failed: Name ✗ ('local_38' ≠ 'extra_return_value2'), Type ✗ ('undefined2' ≠ 'uint')
    Updating variable: iVar3 (int) -> temp_config_value3 (uint)
    ✓ Combined update successful: temp_config_value3 : uint
    ✗ Verification failed: Name ✗ ('iVar3' ≠ 'temp_config_value3'), Type ✗ ('int' ≠ 'uint')
    Updating variable: local_36 (undefined2) -> config_value1 (uint)
    ✓ Combined update successful: config_value1 : uint
    ✗ Verification failed: Name ✗ ('local_36' ≠ 'config_value1'), Type ✗ ('undefined2' ≠ 'uint')
    Updating variable: iVar2 (int) -> extra_return_value1 (uint)
    ✓ Combined update successful: extra_return_value1 : uint
    ✗ Verification failed: Name ✗ ('iVar2' ≠ 'extra_return_value1'), Type ✗ ('int' ≠ 'uint')
    Updating variable: local_34 (ushort) -> puVar2 (uint *)
    ✓ Combined update successful: puVar2 : uint *
    ✗ Verification failed: Name ✗ ('local_34' ≠ 'puVar2'), Type ✗ ('ushort' ≠ 'uint *')
    Updating variable: local_32 (undefined1) -> temp_config_value2 (uint)
    ✓ Combined update successful: temp_config_value2 : uint
    ✗ Verification failed: Name ✗ ('local_32' ≠ 'temp_config_value2'), Type ✗ ('undefined1' ≠ 'uint')
    Updating variable: puVar1 (undefined8 *) -> uVar1 (uint)
    ✓ Combined update successful: uVar1 : uint
    ✗ Verification failed: Name ✗ ('puVar1' ≠ 'uVar1'), Type ✗ ('undefined8 *' ≠ 'uint')
    Updating variable: local_30 (undefined1) -> auStack_50 (undefined1[12])
    ✓ Combined update successful: auStack_50 : undefined1[12]
    ✗ Verification failed: Name ✗ ('local_30' ≠ 'auStack_50'), Type ✗ ('undefined1' ≠ 'undefined1[12]')
    Updating variable: local_28 (undefined1 *) -> temp_config_value1 (uint)
    ✓ Combined update successful: temp_config_value1 : uint
    ✗ Verification failed: Name ✗ ('local_28' ≠ 'temp_config_value1'), Type ✗ ('undefined1 *' ≠ 'uint')
    Updating variable: local_24 (undefined8 *) -> auStack_472 (undefined1[1058])
    ✗ Combined update failed: ghidra.util.exception.InvalidInputException: Data type does not fit within variable stack constraints
    ✗ Type-only fallback also failed: ghidra.util.exception.InvalidInputException: Data type does not fit within variable stack constraints
    Updating variable: local_20 (undefined8 *) -> uStack_474 (undefined2)
    ✓ Combined update successful: uStack_474 : undefined2
    ✗ Verification failed: Name ✗ ('local_20' ≠ 'uStack_474'), Type ✗ ('undefined8 *' ≠ 'undefined2')
  ✓ Applied 0/0 variable updates to configurePeripheralSubsystems
  → 22 current variables and 28 enhanced variables remain unmatched
  Attempting alternative symbol-based variable updates...
  Alternative variable naming for configurePeripheralSubsystems
    Found 0 current vars, 28 enhanced vars
    Alternative approach inner error: 'ghidra.program.database.function.ParameterDB' object has no attribute 'isParameter'
    ⚠ Alternative approach: no variables were successfully updated
Applying enhanced definition to FUN_000636e6 -> process_peripheral_data
  Attempting decompiler-based variable updates...
  Applying variables to process_peripheral_data
  Function process_peripheral_data: 93 current variables, 120 enhanced variables
    Current variables:
      1. extraout_r1 : int (storage: r1:4)
      2. extraout_r1_00 : int (storage: r1:4)
      3. uVar5 : uint (storage: r0:4)
      4. uVar6 : uint (storage: r0:4)
      5. uVar7 : undefined4 (storage: r1:4)
      6. input_data : uint * (storage: r2:4)
      7. extraout_r1_01 : int (storage: r1:4)
      8. extraout_r1_02 : int (storage: r1:4)
      9. iStack_1c : int (storage: Stack[-0x1c]:4)
      10. uStack_24 : uint (storage: Stack[-0x24]:4)
      11. uVar3 : undefined4 (storage: r0:4)
      12. iVar4 : int (storage: r0:4)
      13. puVar1 : undefined4 * (storage: unique:10000fbb:4)
      14. bVar2 : bool (storage: r0:1)
      15. iVar9 : int (storage: r4:4)
      16. iVar10 : int (storage: r5:4)
      17. puVar8 : undefined4 * (storage: r2:4)
      18. peripheral_config : uint * (storage: r3:4)
      19. uVar13 : undefined8 (storage: r1:4,r0:4)
      20. uVar14 : undefined8 (storage: r1:4,r0:4)
      21. puVar11 : undefined8 * (storage: r7:4)
      22. cVar12 : char (storage: tmpCY:1)
      23. local_448 : uint (storage: Stack[-0x448]:4)