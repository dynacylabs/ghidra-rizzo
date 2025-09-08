Testing variable updates for function: RENAMED_HAL_UART_Init
============================================================
CURRENT VARIABLES:
  1. huart_00 : int *
      Storage: r0:4
      Symbol type: <java class 'ghidra.program.model.pcode.HighSymbol'>
      Has setName: False
  2. huart_local : UART_HandleTypeDef *
      Storage: Stack[-0xc]:4
      Symbol type: <java class 'ghidra.program.model.pcode.HighSymbol'>
      Has setName: False
  3. iVar1 : int
      Storage: r3:4
      Symbol type: <java class 'ghidra.program.model.pcode.HighSymbol'>
      Has setName: False

TESTING UPDATE: huart_00 -> huart_00_RENAMED
----------------------------------------
Method 1: updateDBVariable
  Result: huart_00 -> huart_00
  Success: False

Method 2: symbol.setName - Not available

Method 3: variable.setName - No getVariable method

============================================================
Debug test complete
RizzoDebugVariableUpdate.py> Finished!









     3. PriorityGroup_local : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
      4. uVar1 : uint (storage: r3:4)
      5. PreemptPriority_local : typedef uint32_t __uint32_t (storage: Stack[-0x20]:4)
      6. uVar2 : uint (storage: r3:4)
      7. SubPriority_local : typedef uint32_t __uint32_t (storage: Stack[-0x24]:4)
      8. PriorityGroupTmp : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
  Failed to apply variables to NVIC_EncodePriority: unhashable type: 'dict'
Applying enhanced definition to SysTick_Config -> SysTick_Config
  Function SysTick_Config: 2 current variables, 2 enhanced variables
    Current variables:
      1. bVar1 : bool (storage: tmpCY:1)
      2. ticks_local : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
    Enhanced variables:
      1. bVar1 : bool (storage: tmpCY:1)
      2. ticks_local : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
  Failed to apply variables to SysTick_Config: unhashable type: 'dict'
Applying enhanced definition to HAL_NVIC_SetPriorityGrouping -> HAL_NVIC_SetPriorityGrouping
  Function HAL_NVIC_SetPriorityGrouping: 1 current variables, 1 enhanced variables
    Current variables:
      1. PriorityGroup_local : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
    Enhanced variables:
      1. PriorityGroup_local : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
  Failed to apply variables to HAL_NVIC_SetPriorityGrouping: unhashable type: 'dict'
Applying enhanced definition to HAL_NVIC_SetPriority -> HAL_NVIC_SetPriority
  Function HAL_NVIC_SetPriority: 5 current variables, 5 enhanced variables
    Current variables:
      1. iVar1 : int (storage: r0:4)
      2. prioritygroup : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      3. IRQn_local : IRQn_Type (storage: Stack[-0x11]:1)
      4. PreemptPriority_local : typedef uint32_t __uint32_t (storage: Stack[-0x18]:4)
      5. SubPriority_local : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
    Enhanced variables:
      1. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      2. prioritygroup : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      3. IRQn_local : IRQn_Type (storage: Stack[-0x11]:1)
      4. PreemptPriority_local : typedef uint32_t __uint32_t (storage: Stack[-0x18]:4)
      5. SubPriority_local : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
  Failed to apply variables to HAL_NVIC_SetPriority: unhashable type: 'dict'
Applying enhanced definition to HAL_NVIC_EnableIRQ -> HAL_NVIC_EnableIRQ
  Function HAL_NVIC_EnableIRQ: 1 current variables, 1 enhanced variables
    Current variables:
      1. IRQn_local : IRQn_Type (storage: Stack[-0x9]:1)
    Enhanced variables:
      1. IRQn_local : IRQn_Type (storage: Stack[-0x9]:1)
  Failed to apply variables to HAL_NVIC_EnableIRQ: unhashable type: 'dict'
Applying enhanced definition to HAL_SYSTICK_Config -> HAL_SYSTICK_Config
  Function HAL_SYSTICK_Config: 2 current variables, 2 enhanced variables
    Current variables:
      1. TicksNumb_local : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      2. iVar1 : int (storage: r0:4)
    Enhanced variables:
      1. TicksNumb_local : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      2. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
  Failed to apply variables to HAL_SYSTICK_Config: unhashable type: 'dict'
Applying enhanced definition to atexit -> atexit
  Function atexit: 1 current variables, 1 enhanced variables
    Current variables:
      1. iVar1 : int (storage: r0:4)
    Enhanced variables:
      1. iVar1 : int (storage: r0:4)
  Failed to apply variables to atexit: unhashable type: 'dict'
Applying enhanced definition to __libc_fini_array -> __libc_fini_array
  Function __libc_fini_array: 2 current variables, 2 enhanced variables
    Current variables:
      1. iVar1 : int (storage: r4:4)
      2. puVar2 : undefined4 * (storage: r5:4)
    Enhanced variables:
      1. iVar1 : int (storage: r4:4)
      2. puVar2 : undefined4 * (storage: r5:4)
  Failed to apply variables to __libc_fini_array: unhashable type: 'dict'
Applying enhanced definition to __libc_init_array -> __libc_init_array
  Function __libc_init_array: 4 current variables, 4 enhanced variables
    Current variables:
      1. in_r0 : EVP_PKEY_CTX * (storage: r0:4)
      2. iVar1 : int (storage: r4:4)
      3. puVar2 : undefined4 * (storage: r5:4)
      4. iVar3 : int (storage: r6:4)
    Enhanced variables:
      1. in_r0 : EVP_PKEY_CTX * (storage: r0:4)
      2. iVar1 : int (storage: r4:4)
      3. puVar2 : undefined4 * (storage: r5:4)
      4. iVar3 : int (storage: r6:4)
  Failed to apply variables to __libc_init_array: unhashable type: 'dict'
Applying enhanced definition to __register_exitproc -> __register_exitproc
  Function __register_exitproc: 5 current variables, 5 enhanced variables
    Current variables:
      1. iVar5 : int (storage: r5:4)
      2. uVar1 : uint (storage: r0:4)
      3. uVar2 : uint (storage: r2:4)
      4. iVar3 : int (storage: r3:4)
      5. iVar4 : int (storage: r4:4)
    Enhanced variables:
      1. uVar1 : uint (storage: r0:4)
      2. uVar2 : uint (storage: r2:4)
      3. iVar3 : int (storage: r3:4)
      4. iVar4 : int (storage: r4:4)
      5. iVar5 : int (storage: r5:4)
  Failed to apply variables to __register_exitproc: unhashable type: 'dict'
Applying enhanced definition to register_fini -> register_fini
Applying enhanced definition to __aeabi_uldivmod -> __aeabi_uldivmod
  Function __aeabi_uldivmod: 5 current variables, 3 enhanced variables
    Current variables:
      1. in_r0 : int (storage: r0:4)
      2. iVar1 : int (storage: r0:4)
      3. in_r1 : int (storage: r1:4)
      4. in_r2 : int * (storage: r2:4)
      5. in_r3 : int (storage: r3:4)
    Enhanced variables:
      1. uStack_8 : ulonglong (storage: Stack[-0x8]:8)
      2. uVar1 : undefined4 (storage: r0:4)
      3. uVar2 : ulonglong (storage: r1:4,r0:4)
  Failed to apply variables to __aeabi_uldivmod: unhashable type: 'dict'
Applying enhanced definition to HAL_RCC_GetSysClockFreq -> HAL_RCC_GetSysClockFreq
  Function HAL_RCC_GetSysClockFreq: 5 current variables, 8 enhanced variables
    Current variables:
      1. pllm : typedef uint32_t __uint32_t (storage: Stack[-0x2c]:4)
      2. pllvco : typedef uint32_t __uint32_t (storage: Stack[-0x24]:4)
      3. pllp : typedef uint32_t __uint32_t (storage: Stack[-0x30]:4)
      4. sysclockfreq : typedef uint32_t __uint32_t (storage: Stack[-0x28]:4)
      5. uVar1 : uint (storage: r4:4)
    Enhanced variables:
      1. pllm : typedef uint32_t __uint32_t (storage: Stack[-0x2c]:4)
      2. pllvco : typedef uint32_t __uint32_t (storage: Stack[-0x24]:4)
      3. pllp : typedef uint32_t __uint32_t (storage: Stack[-0x30]:4)
      4. sysclockfreq : typedef uint32_t __uint32_t (storage: Stack[-0x28]:4)
      5. lVar1 : longlong (storage: unique:000c8b00:8)
      6. uVar2 : uint (storage: r1:4)
      7. uVar3 : uint (storage: r4:4)
      8. uVar4 : uint (storage: r4:4)
  Failed to apply variables to HAL_RCC_GetSysClockFreq: unhashable type: 'dict'
Applying enhanced definition to HAL_GPIO_Init -> HAL_GPIO_Init
  Function HAL_GPIO_Init: 10 current variables, 10 enhanced variables
    Current variables:
      1. GPIO_Init_local : GPIO_InitTypeDef * (storage: Stack[-0x28]:4)
      2. uVar1 : uint (storage: r3:4)
      3. uVar2 : uint (storage: r3:4)
      4. iVar3 : int (storage: r3:4)
      5. position : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      6. ioposition : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      7. iocurrent : typedef uint32_t __uint32_t (storage: Stack[-0x18]:4)
      8. temp : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      9. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
      10. GPIOx_local : GPIO_TypeDef * (storage: Stack[-0x24]:4)
    Enhanced variables:
      1. GPIO_Init_local : GPIO_InitTypeDef * (storage: Stack[-0x28]:4)
      2. uVar1 : uint (storage: r3:4)
      3. uVar2 : uint (storage: r3:4)
      4. iVar3 : int (storage: r3:4)
      5. position : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      6. ioposition : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      7. iocurrent : typedef uint32_t __uint32_t (storage: Stack[-0x18]:4)
      8. temp : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      9. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
      10. GPIOx_local : GPIO_TypeDef * (storage: Stack[-0x24]:4)
  Failed to apply variables to HAL_GPIO_Init: unhashable type: 'dict'
Applying enhanced definition to HAL_GPIO_Init -> HAL_GPIO_Init
  Function HAL_GPIO_Init: 10 current variables, 10 enhanced variables
    Current variables:
      1. GPIO_Init_local : GPIO_InitTypeDef * (storage: Stack[-0x28]:4)
      2. uVar1 : uint (storage: r3:4)
      3. uVar2 : uint (storage: r3:4)
      4. iVar3 : int (storage: r3:4)
      5. position : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      6. ioposition : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      7. iocurrent : typedef uint32_t __uint32_t (storage: Stack[-0x18]:4)
      8. temp : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      9. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
      10. GPIOx_local : GPIO_TypeDef * (storage: Stack[-0x24]:4)
    Enhanced variables:
      1. GPIO_Init_local : GPIO_InitTypeDef * (storage: Stack[-0x28]:4)
      2. uVar1 : uint (storage: r3:4)
      3. uVar2 : uint (storage: r3:4)
      4. iVar3 : int (storage: r3:4)
      5. position : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      6. ioposition : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      7. iocurrent : typedef uint32_t __uint32_t (storage: Stack[-0x18]:4)
      8. temp : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      9. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
      10. GPIOx_local : GPIO_TypeDef * (storage: Stack[-0x24]:4)
  Failed to apply variables to HAL_GPIO_Init: unhashable type: 'dict'
Applying enhanced definition to SystemClock_Config -> SystemClock_Config
  Function SystemClock_Config: 6 current variables, 6 enhanced variables
    Current variables:
      1. iVar1 : int (storage: r0:4)
      2. RCC_ClkInitStruct : /DWARF/stm32f4xx_hal_rcc.h/RCC_ClkInitTypeDef
pack()
Structure RCC_ClkInitTypeDef {
   0   uint32_t   4   ClockType   ""
   4   uint32_t   4   SYSCLKSource   ""
   8   uint32_t   4   AHBCLKDivider   ""
   12   uint32_t   4   APB1CLKDivider   ""
   16   uint32_t   4   APB2CLKDivider   ""
}
Length: 20 Alignment: 4
 (storage: Stack[-0x20]:20)
      3. RCC_OscInitStruct : /DWARF/stm32f4xx_hal_rcc.h/RCC_OscInitTypeDef
pack()
Structure RCC_OscInitTypeDef {
   0   uint32_t   4   OscillatorType   ""
   4   uint32_t   4   HSEState   ""
   8   uint32_t   4   LSEState   ""
   12   uint32_t   4   HSIState   ""
   16   uint32_t   4   HSICalibrationValue   ""
   20   uint32_t   4   LSIState   ""
   24   RCC_PLLInitTypeDef   28   PLL   ""
}
Length: 52 Alignment: 4
 (storage: Stack[-0x54]:52)
      4. ret : HAL_StatusTypeDef (storage: Stack[-0x9]:1)
      5. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x58]:4)
      6. tmpreg_1 : typedef uint32_t __uint32_t (storage: Stack[-0x5c]:4)
    Enhanced variables:
      1. HVar1 : HAL_StatusTypeDef (storage: r0:1)
      2. RCC_ClkInitStruct : /DWARF/stm32f4xx_hal_rcc.h/RCC_ClkInitTypeDef
pack()
Structure RCC_ClkInitTypeDef {
   0   uint32_t   4   ClockType   ""
   4   uint32_t   4   SYSCLKSource   ""
   8   uint32_t   4   AHBCLKDivider   ""
   12   uint32_t   4   APB1CLKDivider   ""
   16   uint32_t   4   APB2CLKDivider   ""
}
Length: 20 Alignment: 4
 (storage: Stack[-0x20]:20)
      3. RCC_OscInitStruct : /DWARF/stm32f4xx_hal_rcc.h/RCC_OscInitTypeDef
pack()
Structure RCC_OscInitTypeDef {
   0   uint32_t   4   OscillatorType   ""
   4   uint32_t   4   HSEState   ""
   8   uint32_t   4   LSEState   ""
   12   uint32_t   4   HSIState   ""
   16   uint32_t   4   HSICalibrationValue   ""
   20   uint32_t   4   LSIState   ""
   24   RCC_PLLInitTypeDef   28   PLL   ""
}
Length: 52 Alignment: 4
 (storage: Stack[-0x54]:52)
      4. ret : HAL_StatusTypeDef (storage: Stack[-0x9]:1)
      5. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x58]:4)
      6. tmpreg_1 : typedef uint32_t __uint32_t (storage: Stack[-0x5c]:4)
  Failed to apply variables to SystemClock_Config: unhashable type: 'dict'
Applying enhanced definition to HAL_RCC_OscConfig -> HAL_RCC_OscConfig
  Function HAL_RCC_OscConfig: 8 current variables, 8 enhanced variables
    Current variables:
      1. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      2. iVar3 : int (storage: r3:4)
      3. uVar2 : typedef uint32_t __uint32_t (storage: r0:4)
      4. tickstart : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      5. bVar4 : bool (storage: tmpZR:1)
      6. pwrclkchanged : FlagStatus (storage: Stack[-0x9]:1)
      7. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      8. RCC_OscInitStruct_local : RCC_OscInitTypeDef * (storage: Stack[-0x1c]:4)
    Enhanced variables:
      1. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      2. HVar3 : HAL_StatusTypeDef (storage: r3:1)
      3. uVar2 : typedef uint32_t __uint32_t (storage: r0:4)
      4. tickstart : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      5. bVar4 : bool (storage: tmpZR:1)
      6. pwrclkchanged : FlagStatus (storage: Stack[-0x9]:1)
      7. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      8. RCC_OscInitStruct_local : RCC_OscInitTypeDef * (storage: Stack[-0x1c]:4)
  Failed to apply variables to HAL_RCC_OscConfig: unhashable type: 'dict'
Applying enhanced definition to HAL_RCC_OscConfig -> HAL_RCC_OscConfig
  Function HAL_RCC_OscConfig: 8 current variables, 8 enhanced variables
    Current variables:
      1. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      2. iVar3 : int (storage: r3:4)
      3. uVar2 : typedef uint32_t __uint32_t (storage: r0:4)
      4. tickstart : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      5. bVar4 : bool (storage: tmpZR:1)
      6. pwrclkchanged : FlagStatus (storage: Stack[-0x9]:1)
      7. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      8. RCC_OscInitStruct_local : RCC_OscInitTypeDef * (storage: Stack[-0x1c]:4)
    Enhanced variables:
      1. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      2. HVar3 : HAL_StatusTypeDef (storage: r3:1)
      3. uVar2 : typedef uint32_t __uint32_t (storage: r0:4)
      4. tickstart : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      5. bVar4 : bool (storage: tmpZR:1)
      6. pwrclkchanged : FlagStatus (storage: Stack[-0x9]:1)
      7. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      8. RCC_OscInitStruct_local : RCC_OscInitTypeDef * (storage: Stack[-0x1c]:4)
  Failed to apply variables to HAL_RCC_OscConfig: unhashable type: 'dict'
Applying enhanced definition to HAL_RCC_OscConfig -> HAL_RCC_OscConfig
  Function HAL_RCC_OscConfig: 8 current variables, 8 enhanced variables
    Current variables:
      1. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      2. iVar3 : int (storage: r3:4)
      3. uVar2 : typedef uint32_t __uint32_t (storage: r0:4)
      4. tickstart : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      5. bVar4 : bool (storage: tmpZR:1)
      6. pwrclkchanged : FlagStatus (storage: Stack[-0x9]:1)
      7. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      8. RCC_OscInitStruct_local : RCC_OscInitTypeDef * (storage: Stack[-0x1c]:4)
    Enhanced variables:
      1. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      2. HVar3 : HAL_StatusTypeDef (storage: r3:1)
      3. uVar2 : typedef uint32_t __uint32_t (storage: r0:4)
      4. tickstart : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      5. bVar4 : bool (storage: tmpZR:1)
      6. pwrclkchanged : FlagStatus (storage: Stack[-0x9]:1)
      7. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      8. RCC_OscInitStruct_local : RCC_OscInitTypeDef * (storage: Stack[-0x1c]:4)
  Failed to apply variables to HAL_RCC_OscConfig: unhashable type: 'dict'
Applying enhanced definition to SystemInit -> SystemInit
  Function SystemInit: 0 current variables, 1 enhanced variables
    Enhanced variables:
      1. local_4 : undefined4 (storage: Stack[-0x4]:4)
  Failed to apply variables to SystemInit: unhashable type: 'dict'
Applying enhanced definition to NVIC_SetPriorityGrouping -> NVIC_SetPriorityGrouping
  Function NVIC_SetPriorityGrouping: 3 current variables, 3 enhanced variables
    Current variables:
      1. reg_value : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      2. PriorityGroupTmp : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      3. PriorityGroup_local : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
    Enhanced variables:
      1. reg_value : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      2. PriorityGroupTmp : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      3. PriorityGroup_local : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
  Failed to apply variables to NVIC_SetPriorityGrouping: unhashable type: 'dict'
Applying enhanced definition to SysTick_Config -> SysTick_Config
  Function SysTick_Config: 2 current variables, 2 enhanced variables
    Current variables:
      1. bVar1 : bool (storage: tmpCY:1)
      2. ticks_local : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
    Enhanced variables:
      1. bVar1 : bool (storage: tmpCY:1)
      2. ticks_local : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
  Failed to apply variables to SysTick_Config: unhashable type: 'dict'
Applying enhanced definition to __do_global_dtors_aux -> __do_global_dtors_aux
  Function __do_global_dtors_aux: 2 current variables, 1 enhanced variables
    Current variables:
      1. pcVar1 : char * (storage: unique:1000000f:4)
      2. in_r0 : int (storage: r0:4)
    Enhanced variables:
      1. pcVar1 : char * (storage: unique:1000000f:4)
  Failed to apply variables to __do_global_dtors_aux: unhashable type: 'dict'
Applying enhanced definition to frame_dummy -> frame_dummy
Applying enhanced definition to __aeabi_uldivmod -> __aeabi_uldivmod
  Function __aeabi_uldivmod: 5 current variables, 3 enhanced variables
    Current variables:
      1. in_r0 : int (storage: r0:4)
      2. iVar1 : int (storage: r0:4)
      3. in_r1 : int (storage: r1:4)
      4. in_r2 : int * (storage: r2:4)
      5. in_r3 : int (storage: r3:4)
    Enhanced variables:
      1. uStack_8 : ulonglong (storage: Stack[-0x8]:8)
      2. uVar1 : undefined4 (storage: r0:4)
      3. uVar2 : ulonglong (storage: r1:4,r0:4)
  Failed to apply variables to __aeabi_uldivmod: unhashable type: 'dict'
Applying enhanced definition to __divdi3 -> __divdi3
  Function __divdi3: 14 current variables, 15 enhanced variables
    Current variables:
      1. lVar1 : longlong (storage: unique:000c8b00:8)
      2. uVar2 : uint (storage: r0:4)
      3. uVar3 : uint (storage: r1:4)
      4. in_r2 : uint (storage: r2:4)
      5. uVar4 : uint (storage: r2:4)
      6. in_r3 : uint (storage: r3:4)
      7. iVar5 : int (storage: r3:4)
      8. uVar6 : uint (storage: r3:4)
      9. uVar7 : uint (storage: r3:4)
      10. uVar8 : uint (storage: r5:4)
      11. uVar9 : uint (storage: r6:4)
      12. uVar10 : uint (storage: r7:4)
      13. uVar11 : uint (storage: lr:4)
      14. bVar12 : bool (storage: tmpCY:1)
    Enhanced variables:
      1. lVar1 : longlong (storage: unique:000c8b00:8)
      2. uVar2 : uint (storage: r0:4)
      3. uVar3 : uint (storage: r1:4)
      4. uVar4 : uint (storage: r2:4)
      5. iVar5 : int (storage: r3:4)
      6. uVar6 : uint (storage: r3:4)
      7. uVar7 : uint (storage: r3:4)
      8. uVar8 : uint (storage: r5:4)
      9. uVar9 : uint (storage: r5:4)
      10. uVar10 : uint (storage: r6:4)
      11. uVar11 : uint (storage: r7:4)
      12. uVar12 : uint (storage: r12:4)
      13. uVar13 : uint (storage: lr:4)
      14. uVar14 : uint (storage: lr:4)
      15. bVar15 : bool (storage: tmpCY:1)
  Failed to apply variables to __divdi3: unhashable type: 'dict'
Applying enhanced definition to __udivdi3 -> __udivdi3
  Function __udivdi3: 13 current variables, 14 enhanced variables
    Current variables:
      1. lVar1 : longlong (storage: unique:000c8b00:8)
      2. uVar2 : uint (storage: r0:4)
      3. uVar3 : uint (storage: r1:4)
      4. in_r2 : uint (storage: r2:4)
      5. uVar4 : uint (storage: r2:4)
      6. in_r3 : uint (storage: r3:4)
      7. uVar5 : uint (storage: r3:4)
      8. uVar6 : uint (storage: r3:4)
      9. iVar7 : int (storage: r7:4)
      10. uVar8 : uint (storage: r7:4)
      11. uVar9 : uint (storage: r9:4)
      12. uVar10 : uint (storage: lr:4)
      13. bVar11 : bool (storage: tmpCY:1)
    Enhanced variables:
      1. lVar1 : longlong (storage: unique:000c8b00:8)
      2. uVar2 : uint (storage: r0:4)
      3. uVar3 : uint (storage: r1:4)
      4. uVar4 : uint (storage: r1:4)
      5. uVar5 : uint (storage: r2:4)
      6. uVar6 : uint (storage: r3:4)
      7. uVar7 : uint (storage: r3:4)
      8. uVar8 : uint (storage: r3:4)
      9. uVar9 : uint (storage: r5:4)
      10. iVar10 : int (storage: r7:4)
      11. uVar11 : uint (storage: r7:4)
      12. uVar12 : uint (storage: lr:4)
      13. uVar13 : uint (storage: lr:4)
      14. bVar14 : bool (storage: tmpCY:1)
  Failed to apply variables to __udivdi3: unhashable type: 'dict'
Applying enhanced definition to Reset_Handler -> Reset_Handler
  Function Reset_Handler: 2 current variables, 2 enhanced variables
    Current variables:
      1. iVar1 : int (storage: r1:4)
      2. puVar2 : undefined4 * (storage: r2:4)
    Enhanced variables:
      1. iVar1 : int (storage: r1:4)
      2. puVar2 : undefined4 * (storage: r2:4)
  Failed to apply variables to Reset_Handler: unhashable type: 'dict'
Applying enhanced definition to HAL_RCC_ClockConfig -> HAL_RCC_ClockConfig
  Function HAL_RCC_ClockConfig: 7 current variables, 6 enhanced variables
    Current variables:
      1. tickstart : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      2. RCC_ClkInitStruct_local : RCC_ClkInitTypeDef * (storage: Stack[-0x14]:4)
      3. uVar2 : typedef uint32_t __uint32_t (storage: r0:4)
      4. FLatency_local : typedef uint32_t __uint32_t (storage: Stack[-0x18]:4)
      5. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      6. iVar4 : int (storage: r3:4)
      7. uVar3 : uint (storage: r0:4)
    Enhanced variables:
      1. tickstart : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      2. RCC_ClkInitStruct_local : RCC_ClkInitTypeDef * (storage: Stack[-0x14]:4)
      3. uVar2 : typedef uint32_t __uint32_t (storage: r0:4)
      4. FLatency_local : typedef uint32_t __uint32_t (storage: Stack[-0x18]:4)
      5. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      6. HVar3 : HAL_StatusTypeDef (storage: r3:1)
  Failed to apply variables to HAL_RCC_ClockConfig: unhashable type: 'dict'
Applying enhanced definition to HAL_RCC_GetSysClockFreq -> HAL_RCC_GetSysClockFreq
  Function HAL_RCC_GetSysClockFreq: 5 current variables, 8 enhanced variables
    Current variables:
      1. pllm : typedef uint32_t __uint32_t (storage: Stack[-0x2c]:4)
      2. pllvco : typedef uint32_t __uint32_t (storage: Stack[-0x24]:4)
      3. pllp : typedef uint32_t __uint32_t (storage: Stack[-0x30]:4)
      4. sysclockfreq : typedef uint32_t __uint32_t (storage: Stack[-0x28]:4)
      5. uVar1 : uint (storage: r4:4)
    Enhanced variables:
      1. pllm : typedef uint32_t __uint32_t (storage: Stack[-0x2c]:4)
      2. pllvco : typedef uint32_t __uint32_t (storage: Stack[-0x24]:4)
      3. pllp : typedef uint32_t __uint32_t (storage: Stack[-0x30]:4)
      4. sysclockfreq : typedef uint32_t __uint32_t (storage: Stack[-0x28]:4)
      5. lVar1 : longlong (storage: unique:000c8b00:8)
      6. uVar2 : uint (storage: r1:4)
      7. uVar3 : uint (storage: r4:4)
      8. uVar4 : uint (storage: r4:4)
  Failed to apply variables to HAL_RCC_GetSysClockFreq: unhashable type: 'dict'
Applying enhanced definition to HAL_GPIO_Init -> HAL_GPIO_Init
  Function HAL_GPIO_Init: 10 current variables, 10 enhanced variables
    Current variables:
      1. GPIO_Init_local : GPIO_InitTypeDef * (storage: Stack[-0x28]:4)
      2. uVar1 : uint (storage: r3:4)
      3. uVar2 : uint (storage: r3:4)
      4. iVar3 : int (storage: r3:4)
      5. position : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      6. ioposition : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      7. iocurrent : typedef uint32_t __uint32_t (storage: Stack[-0x18]:4)
      8. temp : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      9. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
      10. GPIOx_local : GPIO_TypeDef * (storage: Stack[-0x24]:4)
    Enhanced variables:
      1. GPIO_Init_local : GPIO_InitTypeDef * (storage: Stack[-0x28]:4)
      2. uVar1 : uint (storage: r3:4)
      3. uVar2 : uint (storage: r3:4)
      4. iVar3 : int (storage: r3:4)
      5. position : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      6. ioposition : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      7. iocurrent : typedef uint32_t __uint32_t (storage: Stack[-0x18]:4)
      8. temp : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      9. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
      10. GPIOx_local : GPIO_TypeDef * (storage: Stack[-0x24]:4)
  Failed to apply variables to HAL_GPIO_Init: unhashable type: 'dict'
Applying enhanced definition to HAL_Init -> HAL_Init
Applying enhanced definition to HAL_InitTick -> HAL_InitTick
  Function HAL_InitTick: 2 current variables, 3 enhanced variables
    Current variables:
      1. iVar1 : int (storage: r0:4)
      2. TickPriority_local : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
    Enhanced variables:
      1. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      2. HVar2 : HAL_StatusTypeDef (storage: r3:1)
      3. TickPriority_local : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
  Failed to apply variables to HAL_InitTick: unhashable type: 'dict'
Applying enhanced definition to HAL_IncTick -> HAL_IncTick
  Function HAL_IncTick: 0 current variables, 1 enhanced variables
    Enhanced variables:
      1. local_4 : undefined4 (storage: Stack[-0x4]:4)
  Failed to apply variables to HAL_IncTick: unhashable type: 'dict'
Applying enhanced definition to main -> main
  Function main: 1 current variables, 3 enhanced variables
    Current variables:
      1. iVar1 : int (storage: r0:4)
    Enhanced variables:
      1. HVar2 : HAL_UART_StateTypeDef (storage: r0:1)
      2. HVar1 : HAL_StatusTypeDef (storage: r0:1)
      3. iVar3 : int (storage: r0:4)
  Failed to apply variables to main: unhashable type: 'dict'
Applying enhanced definition to SystemClock_Config -> SystemClock_Config
  Function SystemClock_Config: 6 current variables, 6 enhanced variables
    Current variables:
      1. iVar1 : int (storage: r0:4)
      2. RCC_ClkInitStruct : /DWARF/stm32f4xx_hal_rcc.h/RCC_ClkInitTypeDef
pack()
Structure RCC_ClkInitTypeDef {
   0   uint32_t   4   ClockType   ""
   4   uint32_t   4   SYSCLKSource   ""
   8   uint32_t   4   AHBCLKDivider   ""
   12   uint32_t   4   APB1CLKDivider   ""
   16   uint32_t   4   APB2CLKDivider   ""
}
Length: 20 Alignment: 4
 (storage: Stack[-0x20]:20)
      3. RCC_OscInitStruct : /DWARF/stm32f4xx_hal_rcc.h/RCC_OscInitTypeDef
pack()
Structure RCC_OscInitTypeDef {
   0   uint32_t   4   OscillatorType   ""
   4   uint32_t   4   HSEState   ""
   8   uint32_t   4   LSEState   ""
   12   uint32_t   4   HSIState   ""
   16   uint32_t   4   HSICalibrationValue   ""
   20   uint32_t   4   LSIState   ""
   24   RCC_PLLInitTypeDef   28   PLL   ""
}
Length: 52 Alignment: 4
 (storage: Stack[-0x54]:52)
      4. ret : HAL_StatusTypeDef (storage: Stack[-0x9]:1)
      5. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x58]:4)
      6. tmpreg_1 : typedef uint32_t __uint32_t (storage: Stack[-0x5c]:4)
    Enhanced variables:
      1. HVar1 : HAL_StatusTypeDef (storage: r0:1)
      2. RCC_ClkInitStruct : /DWARF/stm32f4xx_hal_rcc.h/RCC_ClkInitTypeDef
pack()
Structure RCC_ClkInitTypeDef {
   0   uint32_t   4   ClockType   ""
   4   uint32_t   4   SYSCLKSource   ""
   8   uint32_t   4   AHBCLKDivider   ""
   12   uint32_t   4   APB1CLKDivider   ""
   16   uint32_t   4   APB2CLKDivider   ""
}
Length: 20 Alignment: 4
 (storage: Stack[-0x20]:20)
      3. RCC_OscInitStruct : /DWARF/stm32f4xx_hal_rcc.h/RCC_OscInitTypeDef
pack()
Structure RCC_OscInitTypeDef {
   0   uint32_t   4   OscillatorType   ""
   4   uint32_t   4   HSEState   ""
   8   uint32_t   4   LSEState   ""
   12   uint32_t   4   HSIState   ""
   16   uint32_t   4   HSICalibrationValue   ""
   20   uint32_t   4   LSIState   ""
   24   RCC_PLLInitTypeDef   28   PLL   ""
}
Length: 52 Alignment: 4
 (storage: Stack[-0x54]:52)
      4. ret : HAL_StatusTypeDef (storage: Stack[-0x9]:1)
      5. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x58]:4)
      6. tmpreg_1 : typedef uint32_t __uint32_t (storage: Stack[-0x5c]:4)
  Failed to apply variables to SystemClock_Config: unhashable type: 'dict'
Applying enhanced definition to Error_Handler -> Error_Handler
Applying enhanced definition to RENAMED_HAL_UART_Init -> RENAMED_HAL_UART_Init
  Function RENAMED_HAL_UART_Init: 3 current variables, 3 enhanced variables
    Current variables:
      1. huart_00_RENAMED : int * (storage: r0:4)
      2. iVar1 : int (storage: r3:4)
      3. huart_local : UART_HandleTypeDef * (storage: Stack[-0xc]:4)
    Enhanced variables:
      1. huart_00 : UART_HandleTypeDef * (storage: r0:4)
      2. RENAMED_huart_local : char (storage: Stack[-0xc]:1)
      3. RENAMED_iVar1 : char (storage: r3:1)
  Failed to apply variables to RENAMED_HAL_UART_Init: unhashable type: 'dict'
Applying enhanced definition to HAL_UART_IRQHandler -> HAL_UART_IRQHandler
  Function HAL_UART_IRQHandler: 10 current variables, 10 enhanced variables
    Current variables:
      1. iVar1 : int (storage: r0:4)
      2. isrflags : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      3. cr1its : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      4. uVar2 : uint (storage: r3:4)
      5. cr3its : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      6. uVar3 : uint (storage: r3:4)
      7. errorflags : typedef uint32_t __uint32_t (storage: Stack[-0x18]:4)
      8. uVar4 : uint (storage: r3:4)
      9. dmarequest : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
      10. huart_local : UART_HandleTypeDef * (storage: Stack[-0x24]:4)
    Enhanced variables:
      1. HVar1 : HAL_StatusTypeDef (storage: r0:1)
      2. isrflags : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      3. cr1its : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      4. uVar2 : uint (storage: r3:4)
      5. cr3its : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      6. uVar3 : uint (storage: r3:4)
      7. errorflags : typedef uint32_t __uint32_t (storage: Stack[-0x18]:4)
      8. uVar4 : uint (storage: r3:4)
      9. dmarequest : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
      10. huart_local : UART_HandleTypeDef * (storage: Stack[-0x24]:4)
  Failed to apply variables to HAL_UART_IRQHandler: unhashable type: 'dict'
Applying enhanced definition to UART_Transmit_IT -> UART_Transmit_IT
  Function UART_Transmit_IT: 5 current variables, 5 enhanced variables
    Current variables:
      1. sVar1 : short (storage: r3:2)
      2. pbVar2 : byte * (storage: r3:4)
      3. tmp : uint16_t * (storage: Stack[-0xc]:4)
      4. huart_local : UART_HandleTypeDef * (storage: Stack[-0x14]:4)
      5. iVar3 : int (storage: r3:4)
    Enhanced variables:
      1. HVar1 : HAL_StatusTypeDef (storage: r3:1)
      2. tmp : uint16_t * (storage: Stack[-0xc]:4)
      3. uVar2 : typedef uint16_t __uint16_t (storage: r3:2)
      4. huart_local : UART_HandleTypeDef * (storage: Stack[-0x14]:4)
      5. pbVar3 : byte * (storage: r3:4)
  Failed to apply variables to UART_Transmit_IT: unhashable type: 'dict'
Applying enhanced definition to UART_Receive_IT -> UART_Receive_IT
  Function UART_Receive_IT: 6 current variables, 6 enhanced variables
    Current variables:
      1. sVar1 : short (storage: r3:2)
      2. puVar2 : undefined1 * (storage: r3:4)
      3. pbVar3 : byte * (storage: r3:4)
      4. iVar4 : int (storage: r3:4)
      5. tmp : uint16_t * (storage: Stack[-0xc]:4)
      6. huart_local : UART_HandleTypeDef * (storage: Stack[-0x14]:4)
    Enhanced variables:
      1. HVar1 : HAL_StatusTypeDef (storage: r3:1)
      2. uVar2 : typedef uint16_t __uint16_t (storage: r3:2)
      3. puVar3 : uint8_t * (storage: r3:4)
      4. pbVar4 : byte * (storage: r3:4)
      5. tmp : uint16_t * (storage: Stack[-0xc]:4)
      6. huart_local : UART_HandleTypeDef * (storage: Stack[-0x14]:4)
  Failed to apply variables to UART_Receive_IT: unhashable type: 'dict'
Applying enhanced definition to UART_SetConfig -> UART_SetConfig
  Function UART_SetConfig: 15 current variables, 15 enhanced variables
    Current variables:
      1. uVar1 : ulonglong (storage: unique:000c8980:8)
      2. uVar2 : ulonglong (storage: unique:000c8980:8)
      3. uVar3 : ulonglong (storage: unique:000c8980:8)
      4. iVar4 : int (storage: r0:4)
      5. iVar5 : int (storage: r0:4)
      6. iVar6 : int (storage: r0:4)
      7. iVar7 : int (storage: r0:4)
      8. iVar8 : int (storage: r0:4)
      9. iVar9 : int (storage: r3:4)
      10. iVar10 : int (storage: r3:4)
      11. iVar11 : int (storage: r3:4)
      12. iVar12 : int (storage: r3:4)
      13. iVar13 : int (storage: r4:4)
      14. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
      15. huart_local : UART_HandleTypeDef * (storage: Stack[-0x24]:4)
    Enhanced variables:
      1. uVar1 : ulonglong (storage: unique:000c8980:8)
      2. uVar2 : ulonglong (storage: unique:000c8980:8)
      3. uVar3 : ulonglong (storage: unique:000c8980:8)
      4. uVar4 : typedef uint32_t __uint32_t (storage: r0:4)
      5. uVar5 : typedef uint32_t __uint32_t (storage: r0:4)
      6. uVar6 : typedef uint32_t __uint32_t (storage: r0:4)
      7. uVar7 : typedef uint32_t __uint32_t (storage: r0:4)
      8. uVar8 : typedef uint32_t __uint32_t (storage: r0:4)
      9. uVar9 : typedef uint32_t __uint32_t (storage: r3:4)
      10. uVar10 : typedef uint32_t __uint32_t (storage: r3:4)
      11. uVar11 : typedef uint32_t __uint32_t (storage: r3:4)
      12. uVar12 : typedef uint32_t __uint32_t (storage: r3:4)
      13. pUVar13 : USART_TypeDef * (storage: r4:4)
      14. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
      15. huart_local : UART_HandleTypeDef * (storage: Stack[-0x24]:4)
  Failed to apply variables to UART_SetConfig: unhashable type: 'dict'
Applying enhanced definition to HAL_UART_MspInit -> HAL_UART_MspInit
  Function HAL_UART_MspInit: 5 current variables, 5 enhanced variables
    Current variables:
      1. tmpreg_1 : typedef uint32_t __uint32_t (storage: Stack[-0x24]:4)
      2. tmpreg_2 : typedef uint32_t __uint32_t (storage: Stack[-0x28]:4)
      3. huart_local : UART_HandleTypeDef * (storage: Stack[-0x2c]:4)
      4. GPIO_InitStruct : /DWARF/stm32f4xx_hal_gpio.h/GPIO_InitTypeDef
pack()
Structure GPIO_InitTypeDef {
   0   uint32_t   4   Pin   ""
   4   uint32_t   4   Mode   ""
   8   uint32_t   4   Pull   ""
   12   uint32_t   4   Speed   ""
   16   uint32_t   4   Alternate   ""
}
Length: 20 Alignment: 4
 (storage: Stack[-0x1c]:20)
      5. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x20]:4)
    Enhanced variables:
      1. tmpreg_1 : typedef uint32_t __uint32_t (storage: Stack[-0x24]:4)
      2. tmpreg_2 : typedef uint32_t __uint32_t (storage: Stack[-0x28]:4)
      3. huart_local : UART_HandleTypeDef * (storage: Stack[-0x2c]:4)
      4. GPIO_InitStruct : /DWARF/stm32f4xx_hal_gpio.h/GPIO_InitTypeDef
pack()
Structure GPIO_InitTypeDef {
   0   uint32_t   4   Pin   ""
   4   uint32_t   4   Mode   ""
   8   uint32_t   4   Pull   ""
   12   uint32_t   4   Speed   ""
   16   uint32_t   4   Alternate   ""
}
Length: 20 Alignment: 4
 (storage: Stack[-0x1c]:20)
      5. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x20]:4)
  Failed to apply variables to HAL_UART_MspInit: unhashable type: 'dict'
Applying enhanced definition to HAL_RCC_OscConfig -> HAL_RCC_OscConfig
  Function HAL_RCC_OscConfig: 8 current variables, 8 enhanced variables
    Current variables:
      1. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      2. iVar3 : int (storage: r3:4)
      3. uVar2 : typedef uint32_t __uint32_t (storage: r0:4)
      4. tickstart : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      5. bVar4 : bool (storage: tmpZR:1)
      6. pwrclkchanged : FlagStatus (storage: Stack[-0x9]:1)
      7. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      8. RCC_OscInitStruct_local : RCC_OscInitTypeDef * (storage: Stack[-0x1c]:4)
    Enhanced variables:
      1. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      2. HVar3 : HAL_StatusTypeDef (storage: r3:1)
      3. uVar2 : typedef uint32_t __uint32_t (storage: r0:4)
      4. tickstart : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      5. bVar4 : bool (storage: tmpZR:1)
      6. pwrclkchanged : FlagStatus (storage: Stack[-0x9]:1)
      7. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
      8. RCC_OscInitStruct_local : RCC_OscInitTypeDef * (storage: Stack[-0x1c]:4)
  Failed to apply variables to HAL_RCC_OscConfig: unhashable type: 'dict'
Applying enhanced definition to HAL_PWREx_EnableOverDrive -> HAL_PWREx_EnableOverDrive
  Function HAL_PWREx_EnableOverDrive: 4 current variables, 4 enhanced variables
    Current variables:
      1. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      2. uVar2 : typedef uint32_t __uint32_t (storage: r0:4)
      3. tickstart : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      4. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
    Enhanced variables:
      1. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      2. uVar2 : typedef uint32_t __uint32_t (storage: r0:4)
      3. tickstart : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      4. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
  Failed to apply variables to HAL_PWREx_EnableOverDrive: unhashable type: 'dict'
Applying enhanced definition to BSP_LED_Init -> BSP_LED_Init
  Function BSP_LED_Init: 3 current variables, 3 enhanced variables
    Current variables:
      1. gpio_init_structure : /DWARF/stm32f4xx_hal_gpio.h/GPIO_InitTypeDef
pack()
Structure GPIO_InitTypeDef {
   0   uint32_t   4   Pin   ""
   4   uint32_t   4   Mode   ""
   8   uint32_t   4   Pull   ""
   12   uint32_t   4   Speed   ""
   16   uint32_t   4   Alternate   ""
}
Length: 20 Alignment: 4
 (storage: Stack[-0x1c]:20)
      2. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x20]:4)
      3. Led_local : Led_TypeDef (storage: Stack[-0x21]:1)
    Enhanced variables:
      1. gpio_init_structure : /DWARF/stm32f4xx_hal_gpio.h/GPIO_InitTypeDef
pack()
Structure GPIO_InitTypeDef {
   0   uint32_t   4   Pin   ""
   4   uint32_t   4   Mode   ""
   8   uint32_t   4   Pull   ""
   12   uint32_t   4   Speed   ""
   16   uint32_t   4   Alternate   ""
}
Length: 20 Alignment: 4
 (storage: Stack[-0x1c]:20)
      2. tmpreg : typedef uint32_t __uint32_t (storage: Stack[-0x20]:4)
      3. Led_local : Led_TypeDef (storage: Stack[-0x21]:1)
  Failed to apply variables to BSP_LED_Init: unhashable type: 'dict'
Applying enhanced definition to BSP_LED_On -> BSP_LED_On
  Function BSP_LED_On: 1 current variables, 1 enhanced variables
    Current variables:
      1. Led_local : Led_TypeDef (storage: Stack[-0x9]:1)
    Enhanced variables:
      1. Led_local : Led_TypeDef (storage: Stack[-0x9]:1)
  Failed to apply variables to BSP_LED_On: unhashable type: 'dict'
Applying enhanced definition to USART1_IRQHandler -> USART1_IRQHandler
Applying enhanced definition to SystemInit -> SystemInit
  Function SystemInit: 0 current variables, 1 enhanced variables
    Enhanced variables:
      1. local_4 : undefined4 (storage: Stack[-0x4]:4)
  Failed to apply variables to SystemInit: unhashable type: 'dict'
Applying enhanced definition to NVIC_SetPriorityGrouping -> NVIC_SetPriorityGrouping
  Function NVIC_SetPriorityGrouping: 3 current variables, 3 enhanced variables
    Current variables:
      1. reg_value : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      2. PriorityGroupTmp : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      3. PriorityGroup_local : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
    Enhanced variables:
      1. reg_value : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
      2. PriorityGroupTmp : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      3. PriorityGroup_local : typedef uint32_t __uint32_t (storage: Stack[-0x14]:4)
  Failed to apply variables to NVIC_SetPriorityGrouping: unhashable type: 'dict'
Applying enhanced definition to NVIC_SetPriority -> NVIC_SetPriority
  Function NVIC_SetPriority: 2 current variables, 2 enhanced variables
    Current variables:
      1. IRQn_local : IRQn_Type (storage: Stack[-0x9]:1)
      2. priority_local : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
    Enhanced variables:
      1. IRQn_local : IRQn_Type (storage: Stack[-0x9]:1)
      2. priority_local : typedef uint32_t __uint32_t (storage: Stack[-0x10]:4)
  Failed to apply variables to NVIC_SetPriority: unhashable type: 'dict'
Applying enhanced definition to SysTick_Config -> SysTick_Config
  Function SysTick_Config: 2 current variables, 2 enhanced variables
    Current variables:
      1. bVar1 : bool (storage: tmpCY:1)
      2. ticks_local : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
    Enhanced variables:
      1. bVar1 : bool (storage: tmpCY:1)
      2. ticks_local : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
  Failed to apply variables to SysTick_Config: unhashable type: 'dict'
Applying enhanced definition to HAL_NVIC_SetPriority -> HAL_NVIC_SetPriority
  Function HAL_NVIC_SetPriority: 5 current variables, 5 enhanced variables
    Current variables:
      1. iVar1 : int (storage: r0:4)
      2. prioritygroup : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      3. IRQn_local : IRQn_Type (storage: Stack[-0x11]:1)
      4. PreemptPriority_local : typedef uint32_t __uint32_t (storage: Stack[-0x18]:4)
      5. SubPriority_local : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
    Enhanced variables:
      1. uVar1 : typedef uint32_t __uint32_t (storage: r0:4)
      2. prioritygroup : typedef uint32_t __uint32_t (storage: Stack[-0xc]:4)
      3. IRQn_local : IRQn_Type (storage: Stack[-0x11]:1)
      4. PreemptPriority_local : typedef uint32_t __uint32_t (storage: Stack[-0x18]:4)
      5. SubPriority_local : typedef uint32_t __uint32_t (storage: Stack[-0x1c]:4)
  Failed to apply variables to HAL_NVIC_SetPriority: unhashable type: 'dict'
Applying enhanced definition to __libc_fini_array -> __libc_fini_array
  Function __libc_fini_array: 2 current variables, 2 enhanced variables
    Current variables:
      1. iVar1 : int (storage: r4:4)
      2. puVar2 : undefined4 * (storage: r5:4)
    Enhanced variables:
      1. iVar1 : int (storage: r4:4)
      2. puVar2 : undefined4 * (storage: r5:4)
  Failed to apply variables to __libc_fini_array: unhashable type: 'dict'
Applying enhanced definition to __libc_init_array -> __libc_init_array
  Function __libc_init_array: 4 current variables, 4 enhanced variables
    Current variables:
      1. in_r0 : EVP_PKEY_CTX * (storage: r0:4)
      2. iVar1 : int (storage: r4:4)
      3. puVar2 : undefined4 * (storage: r5:4)
      4. iVar3 : int (storage: r6:4)
    Enhanced variables:
      1. in_r0 : EVP_PKEY_CTX * (storage: r0:4)
      2. iVar1 : int (storage: r4:4)
      3. puVar2 : undefined4 * (storage: r5:4)
      4. iVar3 : int (storage: r6:4)
  Failed to apply variables to __libc_init_array: unhashable type: 'dict'
Applying enhanced definition to __register_exitproc -> __register_exitproc
  Function __register_exitproc: 5 current variables, 5 enhanced variables
    Current variables:
      1. iVar5 : int (storage: r5:4)
      2. uVar1 : uint (storage: r0:4)
      3. uVar2 : uint (storage: r2:4)
      4. iVar3 : int (storage: r3:4)
      5. iVar4 : int (storage: r4:4)
    Enhanced variables:
      1. uVar1 : uint (storage: r0:4)
      2. uVar2 : uint (storage: r2:4)
      3. iVar3 : int (storage: r3:4)
      4. iVar4 : int (storage: r4:4)
      5. iVar5 : int (storage: r5:4)
  Failed to apply variables to __register_exitproc: unhashable type: 'dict'
Applying enhanced definition to register_fini -> register_fini
Applied enhanced definitions to 109 functions
Renamed 0 functions
Applied variable updates for 422 variables
RizzoApplyEnhanced.py> Finished!
