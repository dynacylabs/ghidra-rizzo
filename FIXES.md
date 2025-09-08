# Rizzo Apply Fixes

## Issues Resolved

The `rizzo_apply.py` script was experiencing multiple **DuplicateNameException** errors when trying to apply enhanced function signatures, particularly during variable name updates.

### Root Causes Identified

1. **Name Conflict Management**: The script was not properly tracking variable names that were being assigned during the same function processing batch, leading to multiple variables trying to claim the same name.

2. **Double Matching**: Enhanced variables could be matched to multiple current symbols, causing conflicts and duplicate applications.

3. **Insufficient Conflict Resolution**: When name conflicts were detected, the fallback strategy wasn't robust enough.

### Fixes Implemented

#### 1. Enhanced Name Tracking System

- Added `reserved_names` parameter to track all names currently in use
- Names are reserved before updates begin and updated dynamically during processing
- Prevents race conditions where multiple variables try to claim the same name

#### 2. Improved Matching Strategy

- **Before**: Used separate tracking sets that could overlap
- **After**: Uses unified tracking with `matched_symbols` set and `used_enhanced_vars` set
- Prevents double-matching of symbols and enhanced variables

#### 3. Better Conflict Resolution

**Before:**
```python
if new_name not in existing_names:
    final_name = new_name
else:
    # Keep old name (limited fallback)
    print("Warning: Name already exists, keeping original")
```

**After:**
```python
if new_name not in reserved_names:
    final_name = new_name
else:
    # Try numbered alternatives
    counter = 1
    while f"{new_name}_{counter}" in reserved_names and counter < 100:
        counter += 1
    if counter < 100:
        final_name = f"{new_name}_{counter}"
```

#### 4. Enhanced Error Handling

- Added specific handling for `DuplicateNameException` errors
- Improved fallback strategies for combined name+type updates
- Better error reporting with more detailed status messages

#### 5. Duplicate Detection

- Pre-analysis of enhanced variable data to detect and warn about duplicate names
- Early warning system that alerts users to potential conflicts before processing begins

### Expected Improvements

1. **Reduced Errors**: Should eliminate most `DuplicateNameException` errors
2. **Better Success Rate**: More variables should be successfully updated
3. **Clearer Output**: Better reporting of what succeeded, what failed, and why
4. **Conflict Resolution**: Automatic resolution of name conflicts with numbered alternatives

### Usage Notes

The script will now:

1. Analyze enhanced data for potential conflicts before processing
2. Display warnings about duplicate names in the enhanced data
3. Automatically generate alternative names when conflicts occur
4. Provide more detailed status reporting during updates

### Partial Success Handling

The script recognizes that Ghidra sometimes allows type updates but not name updates due to internal limitations. This is now reported as "Partial success" rather than a failure, with appropriate status messages explaining the limitation.

## Testing

After applying these fixes, you should see:
- Fewer `DuplicateNameException` errors
- More detailed progress reporting
- Better handling of edge cases
- Improved overall success rates for variable updates

To test the improvements, re-run your `rizzo_apply.py` script with the same `.riz1` file that was causing errors before.
