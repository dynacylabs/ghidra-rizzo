#!/usr/bin/env python3
"""
Rizzo Signature File Inspector
=============================

A standalone Python script to inspect and analyze Rizzo signature files (.rizz).
This script can run outside of Ghidra and provides detailed information about
the contents of signature files, including enhanced metadata.

Usage:
    python rizzo_inspector.py <signature_file.rizz> [options]

Options:
    --summary           Show only summary statistics (default)
    --detailed          Show detailed function information
    --functions         List all functions with metadata
    --search <name>     Search for specific function name
    --metadata          Show only functions with enhanced metadata
    --export-csv        Export function data to CSV
    --help              Show this help message
"""

import pickle
import sys
import os
import argparse
import csv
from collections import defaultdict

class RizzoInspector:
    def __init__(self, signature_file):
        """Initialize the inspector with a signature file."""
        self.signature_file = signature_file
        self.signatures = None
        self.load_signatures()
    
    def load_signatures(self):
        """Load signatures from the file."""
        if not os.path.exists(self.signature_file):
            raise FileNotFoundError(f"Signature file not found: {self.signature_file}")
        
        try:
            with open(self.signature_file, 'rb') as f:
                loaded_data = pickle.load(f)
                
            # Handle both object and dictionary formats
            if isinstance(loaded_data, dict):
                # Convert dictionary to object-like access
                class DictAsObject:
                    def __init__(self, d):
                        for k, v in d.items():
                            setattr(self, k, v)
                
                self.signatures = DictAsObject(loaded_data)
            else:
                # Assume it's already an object
                self.signatures = loaded_data
                
            print(f"✓ Successfully loaded signature file: {self.signature_file}")
        except Exception as e:
            raise Exception(f"Failed to load signature file: {e}")
    
    def show_summary(self):
        """Show summary statistics of the signature file."""
        print("\n" + "=" * 60)
        print("RIZZO SIGNATURE FILE SUMMARY")
        print("=" * 60)
        
        print(f"File: {self.signature_file}")
        print(f"Size: {os.path.getsize(self.signature_file):,} bytes")
        
        # Basic signature counts
        print(f"\nSignature Counts:")
        print(f"  Formal signatures:    {len(self.signatures.formal):,}")
        print(f"  Fuzzy signatures:     {len(self.signatures.fuzzy):,}")
        print(f"  String signatures:    {len(self.signatures.strings):,}")
        print(f"  Function signatures:  {len(self.signatures.functions):,}")
        print(f"  Immediate signatures: {len(self.signatures.immediates):,}")
        
        # Duplicate counts
        print(f"\nDuplicate Signature Counts:")
        print(f"  Formal duplicates:    {len(self.signatures.formaldups):,}")
        print(f"  Fuzzy duplicates:     {len(self.signatures.fuzzydups):,}")
        print(f"  String duplicates:    {len(self.signatures.stringdups):,}")
        print(f"  Function duplicates:  {len(getattr(self.signatures, 'functiondups', set())):,}")
        print(f"  Immediate duplicates: {len(self.signatures.immediatedups):,}")
        
        # Function analysis
        print(f"\nFunction Analysis:")
        print(f"  Total functions:      {len(self.signatures.functions):,}")
        
        # Analyze enhanced metadata
        self._analyze_enhanced_metadata()
    
    def _analyze_enhanced_metadata(self):
        """Analyze enhanced metadata in the signature file."""
        enhanced_functions = 0
        signature_metadata = 0
        variable_metadata = 0
        comment_metadata = 0
        
        signature_types = defaultdict(int)
        variable_types = defaultdict(int)
        comment_types = defaultdict(int)
        
        for addr, func_data in self.signatures.functions.items():
            has_enhanced = len(func_data) > 2
            
            if has_enhanced:
                enhanced_functions += 1
                
                # Check signature metadata
                if len(func_data) > 2 and func_data[2]:
                    sig_data = func_data[2]
                    if sig_data.get('return_type') or sig_data.get('parameters') or sig_data.get('calling_convention'):
                        signature_metadata += 1
                        if sig_data.get('return_type'):
                            signature_types['return_type'] += 1
                        if sig_data.get('parameters'):
                            signature_types['parameters'] += 1
                        if sig_data.get('calling_convention'):
                            signature_types['calling_convention'] += 1
                
                # Check variable metadata
                if len(func_data) > 3 and func_data[3]:
                    var_data = func_data[3]
                    if (var_data.get('parameters') or var_data.get('local_variables') or 
                        var_data.get('high_level_symbols')):
                        variable_metadata += 1
                        if var_data.get('parameters'):
                            variable_types['parameters'] += 1
                        if var_data.get('local_variables'):
                            variable_types['local_variables'] += 1
                        if var_data.get('high_level_symbols'):
                            variable_types['high_level_symbols'] += 1
                
                # Check comment metadata
                if len(func_data) > 4:
                    comments = func_data[4:10]
                    if any(comments):
                        comment_metadata += 1
                        comment_names = ['comment', 'plate_comment', 'pre_comment', 
                                       'post_comment', 'eol_comment', 'repeatable_comment']
                        for i, comment in enumerate(comments):
                            if comment and i < len(comment_names):
                                comment_types[comment_names[i]] += 1
        
        print(f"\nEnhanced Metadata Analysis:")
        print(f"  Functions with enhanced data: {enhanced_functions:,}")
        print(f"  Functions with signatures:    {signature_metadata:,}")
        print(f"  Functions with variables:     {variable_metadata:,}")
        print(f"  Functions with comments:      {comment_metadata:,}")
        
        if signature_types:
            print(f"\n  Signature Metadata Breakdown:")
            for sig_type, count in signature_types.items():
                print(f"    {sig_type}: {count:,}")
        
        if variable_types:
            print(f"\n  Variable Metadata Breakdown:")
            for var_type, count in variable_types.items():
                print(f"    {var_type}: {count:,}")
        
        if comment_types:
            print(f"\n  Comment Metadata Breakdown:")
            for comment_type, count in comment_types.items():
                print(f"    {comment_type}: {count:,}")
        
        # Calculate percentages
        total_functions = len(self.signatures.functions)
        if total_functions > 0:
            print(f"\nMetadata Coverage:")
            print(f"  Enhanced metadata:  {enhanced_functions/total_functions*100:.1f}%")
            print(f"  Signature metadata: {signature_metadata/total_functions*100:.1f}%")
            print(f"  Variable metadata:  {variable_metadata/total_functions*100:.1f}%")
            print(f"  Comment metadata:   {comment_metadata/total_functions*100:.1f}%")
    
    def show_functions(self, detailed=False, with_metadata_only=False):
        """Show function information."""
        print("\n" + "=" * 60)
        print("FUNCTION INFORMATION")
        print("=" * 60)
        
        displayed_count = 0
        
        for addr, func_data in self.signatures.functions.items():
            function_name = func_data[0]
            has_enhanced = len(func_data) > 2
            
            # Filter functions if only metadata requested
            if with_metadata_only and not has_enhanced:
                continue
            
            # Basic info
            print(f"\nFunction: {function_name}")
            print(f"  Address: 0x{addr:x}")
            print(f"  Blocks: {len(func_data[1])}")
            
            if has_enhanced and detailed:
                # Show signature metadata
                if len(func_data) > 2 and func_data[2]:
                    sig_data = func_data[2]
                    print(f"  Signature Metadata:")
                    if sig_data.get('return_type'):
                        print(f"    Return Type: {sig_data['return_type']}")
                    if sig_data.get('calling_convention'):
                        print(f"    Calling Convention: {sig_data['calling_convention']}")
                    if sig_data.get('parameters'):
                        print(f"    Parameters: {len(sig_data['parameters'])}")
                        for i, param in enumerate(sig_data['parameters'][:3]):  # Show first 3
                            print(f"      {i}: {param.get('name', 'unnamed')} ({param.get('data_type', 'unknown')})")
                        if len(sig_data['parameters']) > 3:
                            print(f"      ... and {len(sig_data['parameters']) - 3} more")
                
                # Show variable metadata
                if len(func_data) > 3 and func_data[3]:
                    var_data = func_data[3]
                    print(f"  Variable Metadata:")
                    if var_data.get('parameters'):
                        print(f"    Parameters: {len(var_data['parameters'])}")
                    if var_data.get('local_variables'):
                        print(f"    Local Variables: {len(var_data['local_variables'])}")
                    if var_data.get('high_level_symbols'):
                        print(f"    High-Level Symbols: {len(var_data['high_level_symbols'])}")
                
                # Show comment metadata
                if len(func_data) > 4:
                    comments = func_data[4:10]
                    comment_names = ['comment', 'plate_comment', 'pre_comment', 
                                   'post_comment', 'eol_comment', 'repeatable_comment']
                    active_comments = []
                    for i, comment in enumerate(comments):
                        if comment and i < len(comment_names):
                            active_comments.append(comment_names[i])
                    if active_comments:
                        print(f"  Comments: {', '.join(active_comments)}")
            
            elif has_enhanced:
                # Show brief metadata info
                metadata_types = []
                if len(func_data) > 2 and func_data[2]:
                    metadata_types.append("signature")
                if len(func_data) > 3 and func_data[3]:
                    metadata_types.append("variables")
                if len(func_data) > 4 and any(func_data[4:10]):
                    metadata_types.append("comments")
                if metadata_types:
                    print(f"  Metadata: {', '.join(metadata_types)}")
            
            displayed_count += 1
            
            # Limit output for large files
            if displayed_count >= 50 and not detailed:
                remaining = len(self.signatures.functions) - displayed_count
                if remaining > 0:
                    print(f"\n... and {remaining} more functions (use --detailed to see all)")
                break
    
    def search_function(self, search_term):
        """Search for functions by name."""
        print(f"\n" + "=" * 60)
        print(f"SEARCH RESULTS FOR: '{search_term}'")
        print("=" * 60)
        
        found_functions = []
        
        for addr, func_data in self.signatures.functions.items():
            function_name = func_data[0]
            if search_term.lower() in function_name.lower():
                found_functions.append((addr, func_data))
        
        if not found_functions:
            print(f"No functions found matching '{search_term}'")
            return
        
        print(f"Found {len(found_functions)} matching function(s):")
        
        for addr, func_data in found_functions:
            function_name = func_data[0]
            print(f"\nFunction: {function_name}")
            print(f"  Address: 0x{addr:x}")
            print(f"  Blocks: {len(func_data[1])}")
            
            # Show metadata if available
            has_enhanced = len(func_data) > 2
            if has_enhanced:
                metadata_types = []
                if len(func_data) > 2 and func_data[2]:
                    metadata_types.append("signature")
                if len(func_data) > 3 and func_data[3]:
                    metadata_types.append("variables")
                if len(func_data) > 4 and any(func_data[4:10]):
                    metadata_types.append("comments")
                if metadata_types:
                    print(f"  Metadata: {', '.join(metadata_types)}")
    
    def export_to_csv(self, output_file):
        """Export function data to CSV file."""
        print(f"\nExporting function data to {output_file}...")
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'function_name', 'address', 'blocks_count', 'has_signature',
                'return_type', 'calling_convention', 'param_count',
                'has_variables', 'local_vars_count', 'has_comments', 'comment_types'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for addr, func_data in self.signatures.functions.items():
                function_name = func_data[0]
                
                row = {
                    'function_name': function_name,
                    'address': f"0x{addr:x}",
                    'blocks_count': len(func_data[1]),
                    'has_signature': 'No',
                    'return_type': '',
                    'calling_convention': '',
                    'param_count': 0,
                    'has_variables': 'No',
                    'local_vars_count': 0,
                    'has_comments': 'No',
                    'comment_types': ''
                }
                
                # Enhanced metadata
                if len(func_data) > 2 and func_data[2]:
                    sig_data = func_data[2]
                    row['has_signature'] = 'Yes'
                    row['return_type'] = sig_data.get('return_type', '')
                    row['calling_convention'] = sig_data.get('calling_convention', '')
                    row['param_count'] = len(sig_data.get('parameters', []))
                
                if len(func_data) > 3 and func_data[3]:
                    var_data = func_data[3]
                    row['has_variables'] = 'Yes'
                    row['local_vars_count'] = len(var_data.get('local_variables', []))
                
                if len(func_data) > 4 and any(func_data[4:10]):
                    row['has_comments'] = 'Yes'
                    comment_names = ['comment', 'plate_comment', 'pre_comment',
                                   'post_comment', 'eol_comment', 'repeatable_comment']
                    active_comments = []
                    for i, comment in enumerate(func_data[4:10]):
                        if comment and i < len(comment_names):
                            active_comments.append(comment_names[i])
                    row['comment_types'] = ';'.join(active_comments)
                
                writer.writerow(row)
        
        print(f"✓ Successfully exported {len(self.signatures.functions)} functions to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Inspect and analyze Rizzo signature files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python rizzo_inspector.py signatures.rizz
  python rizzo_inspector.py signatures.rizz --detailed
  python rizzo_inspector.py signatures.rizz --search malloc
  python rizzo_inspector.py signatures.rizz --metadata
  python rizzo_inspector.py signatures.rizz --export-csv functions.csv
        """
    )
    
    parser.add_argument('signature_file', help='Path to the Rizzo signature file (.rizz)')
    parser.add_argument('--summary', action='store_true', default=True,
                       help='Show summary statistics (default)')
    parser.add_argument('--detailed', action='store_true',
                       help='Show detailed function information')
    parser.add_argument('--functions', action='store_true',
                       help='List all functions with basic info')
    parser.add_argument('--search', metavar='NAME',
                       help='Search for functions containing NAME')
    parser.add_argument('--metadata', action='store_true',
                       help='Show only functions with enhanced metadata')
    parser.add_argument('--export-csv', metavar='FILE',
                       help='Export function data to CSV file')
    
    args = parser.parse_args()
    
    try:
        inspector = RizzoInspector(args.signature_file)
        
        if args.search:
            inspector.search_function(args.search)
        elif args.functions or args.detailed or args.metadata:
            inspector.show_functions(
                detailed=args.detailed,
                with_metadata_only=args.metadata
            )
        else:
            inspector.show_summary()
        
        if args.export_csv:
            inspector.export_to_csv(args.export_csv)
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
