# Enhanced type mapping utilities for Rizzo multi-stage system
# @author fuzzywalls
# @category TNS

"""
This module provides enhanced C-to-Ghidra type mapping functionality
for the multi-stage Rizzo signature system.
"""

from ghidra.program.model.data import (
    ArrayDataType,
    BooleanDataType,
    CategoryPath,
    CharDataType,
    DataTypeManager,
    DoubleDataType,
    FloatDataType,
    IntegerDataType,
    LongDataType,
    LongLongDataType,
    PointerDataType,
    ShortDataType,
    Structure,
    StructureDataType,
    UnsignedCharDataType,
    UnsignedIntegerDataType,
    UnsignedLongDataType,
    UnsignedLongLongDataType,
    UnsignedShortDataType,
    VoidDataType,
)

def map_c_type_to_ghidra_type(type_string):
    """
    Enhanced C data type to Ghidra data type mapping.
    
    This function converts string representations of C data types to the appropriate 
    Ghidra DataType objects. It handles standard C types, pointer types, array types, 
    and common variations/aliases used in embedded systems and firmware.
    
    Args:
        type_string (str): The C type string to convert (e.g., "int", "char*", "uint32_t")
        
    Returns:
        DataType: The corresponding Ghidra DataType object. Returns IntegerDataType()
                 as a fallback for unrecognized types.
    """
    
    if not type_string:
        return IntegerDataType()
    
    # Clean and normalize the type string
    type_string = type_string.strip()
    original_type = type_string
    
    # Handle array types first (e.g., "int[10]", "char[]")
    if '[' in type_string and ']' in type_string:
        base_type_str = type_string.split('[')[0].strip()
        array_size_str = type_string.split('[')[1].split(']')[0].strip()
        
        base_type = map_c_type_to_ghidra_type(base_type_str)
        
        if array_size_str and array_size_str.isdigit():
            array_size = int(array_size_str)
            return ArrayDataType(base_type, array_size, base_type.getLength())
        else:
            # Variable-length array - treat as pointer
            return PointerDataType(base_type)
    
    # Handle pointer types (e.g., "int*", "char *", "void*")
    if '*' in type_string:
        pointer_count = type_string.count('*')
        base_type_str = type_string.replace('*', '').strip()
        
        base_type = map_c_type_to_ghidra_type(base_type_str)
        
        # Create nested pointers for multiple levels (e.g., "char**")
        result_type = base_type
        for _ in range(pointer_count):
            result_type = PointerDataType(result_type)
        
        return result_type
    
    # Normalize for consistent lookup
    normalized_type = type_string.lower().strip()
    
    # Handle signed/unsigned qualifiers
    is_unsigned = False
    if normalized_type.startswith('unsigned '):
        is_unsigned = True
        normalized_type = normalized_type[9:].strip()  # Remove "unsigned "
    elif normalized_type.startswith('signed '):
        normalized_type = normalized_type[7:].strip()  # Remove "signed "
    
    # Standard integer types
    if normalized_type in ['char', 'int8_t', 'byte']:
        return UnsignedCharDataType() if is_unsigned else CharDataType()
    elif normalized_type in ['short', 'short int', 'int16_t', 'word']:
        return UnsignedShortDataType() if is_unsigned else ShortDataType()
    elif normalized_type in ['int', 'int32_t', 'dword', 'long']:
        return UnsignedIntegerDataType() if is_unsigned else IntegerDataType()
    elif normalized_type in ['long long', 'long long int', 'int64_t', 'qword']:
        return UnsignedLongLongDataType() if is_unsigned else LongLongDataType()
    
    # Fixed-width integer types (common in embedded systems)
    fixed_width_types = {
        'uint8_t': UnsignedCharDataType(),
        'int8_t': CharDataType(),
        'uint16_t': UnsignedShortDataType(),
        'int16_t': ShortDataType(),
        'uint32_t': UnsignedIntegerDataType(),
        'int32_t': IntegerDataType(),
        'uint64_t': UnsignedLongLongDataType(),
        'int64_t': LongLongDataType(),
        'size_t': UnsignedIntegerDataType(),
        'ssize_t': IntegerDataType(),
        'uintptr_t': UnsignedIntegerDataType(),
        'intptr_t': IntegerDataType(),
    }
    
    if normalized_type in fixed_width_types:
        return fixed_width_types[normalized_type]
    
    # Floating-point types
    if normalized_type in ['float']:
        return FloatDataType()
    elif normalized_type in ['double', 'long double']:
        return DoubleDataType()
    
    # Boolean types
    if normalized_type in ['bool', 'boolean', '_bool']:
        return BooleanDataType()
    
    # Void type
    if normalized_type in ['void']:
        return VoidDataType()
    
    # Handle common embedded/firmware specific types
    embedded_types = {
        'byte': UnsignedCharDataType(),
        'word': UnsignedShortDataType(),
        'dword': UnsignedIntegerDataType(),
        'qword': UnsignedLongLongDataType(),
        'u8': UnsignedCharDataType(),
        's8': CharDataType(),
        'u16': UnsignedShortDataType(),
        's16': ShortDataType(),
        'u32': UnsignedIntegerDataType(),
        's32': IntegerDataType(),
        'u64': UnsignedLongLongDataType(),
        's64': LongLongDataType(),
    }
    
    if normalized_type in embedded_types:
        return embedded_types[normalized_type]
    
    # Try to find existing data type in the program's data type manager
    try:
        if hasattr(currentProgram, 'getDataTypeManager'):
            dtm = currentProgram.getDataTypeManager()
            existing_dt = dtm.getDataType(CategoryPath.ROOT, original_type)
            if existing_dt:
                return existing_dt
            
            # Try normalized version
            existing_dt = dtm.getDataType(CategoryPath.ROOT, normalized_type)
            if existing_dt:
                return existing_dt
    except:
        pass
    
    # Fallback to integer type for unknown types
    print(f"Warning: Unknown type '{original_type}', defaulting to int")
    return IntegerDataType()

def get_type_size_info(data_type):
    """
    Get size information for a Ghidra data type.
    
    Args:
        data_type: Ghidra DataType object
        
    Returns:
        dict: Information about the type including size, alignment, etc.
    """
    try:
        return {
            'name': data_type.getName(),
            'size': data_type.getLength(),
            'description': data_type.getDescription(),
            'category': str(data_type.getCategoryPath()),
            'is_pointer': isinstance(data_type, PointerDataType),
            'is_array': isinstance(data_type, ArrayDataType),
            'is_structure': isinstance(data_type, Structure),
        }
    except:
        return {'name': 'unknown', 'size': -1}

def validate_type_mapping(c_type_string):
    """
    Validate that a C type string can be properly mapped to a Ghidra type.
    
    Args:
        c_type_string (str): C type string to validate
        
    Returns:
        bool: True if the type can be mapped, False otherwise
    """
    try:
        ghidra_type = map_c_type_to_ghidra_type(c_type_string)
        return ghidra_type is not None
    except:
        return False
