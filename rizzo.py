import os
import time
import pickle

import utils

from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.symbol import SourceType
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import RefType


def is_code_ref(reference):
    """
    Determine if the reference is code reference.

    :param reference: Reference to inspect.
    :type reference: ghidra.program.model.symbol.Reference

    :returns: True if reference is a code reference, False otherwise.
    :rtype: bool
    """
    ref_type = reference.getReferenceType()
    if ref_type:
        return ref_type.isCall() or ref_type.isConditional() or ref_type.isJump()
    return False


def is_data_ref(reference):
    """
    Determine if the reference is a data reference.

    :param reference: Reference to inspect.
    :type reference: ghidra.program.model.symbol.Reference

    :returns: True if reference is a data reference, False otherwise.
    :rtype: bool
    """
    ref_type = reference.getReferenceType()
    if ref_type:
        return ref_type.isRead() or ref_type.isData()
    return False


def is_call_instruction(instruction):
    """
    Determine if the reference is a function call.

    :param reference: Reference to inspect.
    :type reference: ghidra.program.model.symbol.Reference

    :returns: True if reference is function call, False otherwise.
    :rtype: bool
    """
    flow_type = instruction.getFlowType()
    if flow_type:
        return flow_type.isCall()
    return False


def find_signature_matches(new_signature, curr_signature, new_functions,
                           curr_functions, signature_type, filter_fn=None):
    """
    Search for signature matches between current file signatures and signatures
    loaded from the user provided file.

    :param new_signature: Loaded signature dictionary.
    :type new_signature: dict

    :param curr_signature: Current program signatures to compare against.
    :type curr_signature: dict

    :param new_functions: Function dict from loaded file.
    :type new_functions: dict

    :param curr_functions: Function dict from current program.
    :type curr_functions: dict

    :param signature_type: String representing the signature type.
    :type signature_type: str

    :param filter_fn: Filter function used to ignore matches under given 
                      cirumstances.
    :type filter_fn: function

    :returns: Dictionary of signatures. Key is function in current program, 
              value is the loaded function.
    :rtype: dict
    """
    signature_match = {}

    start = time.time()

    key_error_count = 0

    for signature, function in new_signature.iteritems():
        if signature in curr_signature:
            curr_func = RizzoFunctionDescriptor(curr_signature,
                                                curr_functions,
                                                signature)
            try:
                new_func = RizzoFunctionDescriptor(new_signature,
                                                new_functions,
                                                signature)
            except:
                key_error_count += 1

            if not filter_fn or filter_fn(curr_func, new_func):
                signature_match[curr_func] = new_func

    end = time.time()

    print("Found {signature_match_count} {signature_type} matches in {seconds} "
          "seconds. {key_errors} Key Errors were Encountered."
          .format(signature_match_count=len(signature_match),
                  signature_type=signature_type, seconds=(end - start),
                  key_errors=key_error_count))
    return signature_match


class RizzoBlockDescriptor(object):
    """
    Break signature blocks out to classes to easily reference. Stored in this
    format to limit pickle storage space.
    """

    def __init__(self, block):
        self.formal = block[0]
        self.fuzzy = block[1]
        self.immediates = block[2]
        self.functions = block[3]

    def __eq__(self, block):
        """
        Compare this block to another to check for a match.

        :param block: Block to compare against.
        :type block: RizzoBlockDescriptor

        :returns: True if they match, false otherwise.
        :rtype: bool
        """
        return self.formal == block.formal and \
            len(self.immediates) == len(block.immediates) and \
            len(self.functions) == len(block.functions)


class RizzoFunctionDescriptor(object):
    """
    Break function descriptor out to class to easily reference. 
    """

    def __init__(self, signatures, functions, key):
        self.address = signatures[key]
        self.name = functions[self.address][0]
        self.blocks = functions[self.address][1]


class RizzoSignature(object):
    """
    Store discovered function signatures.
    """

    def __init__(self):
        self.formal = {}
        self.fuzzy = {}
        self.strings = {}
        self.functions = {}
        self.immediates = {}

        self.fuzzydups = set()
        self.formaldups = set()
        self.stringdups = set()
        self.functiondups = set()
        self.immediatedups = set()

    def _add(self, dictionary, dictionary_dups, key, value):
        """
        Add a signature to a dictionary or the duplicate dictionary if it 
        already exists.

        :param dictionary: Default dictionary to add entry to.
        :type dictionary: dict

        :param dictionary_dups: Duplicate dictionary to move to if already 
                                present in `dictionary`.
        :type dictionary_dups: dict

        :param key: Key to insert in dictionary.
        :type key: variable

        :parrm value: Value to set for key.
        :type: value: variable
        """
        if dictionary.has_key(key):
            del dictionary[key]
            dictionary_dups.add(key)
        elif key not in dictionary_dups:
            dictionary[key] = value

    def add_formal(self, signature, address):
        """
        Add formal function signature.

        :param signature: Signature to be added to formal signatures.
        :type signature: int

        :param address: Address of function representing the signature.
        :type address: int
        """
        self._add(self.formal, self.formaldups, signature, address)

    def add_fuzzy(self, signature, address):
        """
        Add fuzzy function signature.

        :param signature: Signature to be added to fuzzy signatures.
        :type signature: int

        :param address: Address of function representing the signature.
        :type address: int
        """
        self._add(self.fuzzy, self.fuzzydups, signature, address)

    def add_string(self, signature, address):
        """
        Add string function signature.

        :param signature: Signature to be added to string signatures.
        :type signature: int

        :param address: Address of function representing the signature.
        :type address: int
        """
        self._add(self.strings, self.stringdups, signature, address)

    def add_function(self, signature, address):
        """
        Add function call signature.

        :param signature: Signature to be added to function call signatures.
        :type signature: int

        :param address: Address of function representing the signature.
        :type address: int
        """
        self._add(self.functions, self.functiondups, signature, address)

    def add_immediate(self, signature, address):
        """
        Add immediate function signature.

        :param signature: Signature to be added to immediate signatures.
        :type signature: int

        :param address: Address of function representing the signature.
        :type address: int
        """
        self._add(self.immediates, self.immediatedups, signature, address)

    def reset_dups(self):
        """
        Reset duplicate signature sets.
        """
        self.fuzzydups = set()
        self.formaldups = set()
        self.stringdups = set()
        self.functionsdups = set()
        self.immediatedups = set()


class RizzoString(object):
    """
    Represents a found string with references to it.
    """

    def __init__(self, addr, value, references):
        self.address = addr
        self.value = value
        self.xrefs = references


class Rizzo(object):
    def __init__(self, program):
        self._program = program
        self._flat_api = FlatProgramAPI(self._program)
        self._memory_map = self._program.getMemory()
        self._simple_blk = BasicBlockModel(self._program)
        self._monitor = self._flat_api.getMonitor()
        self._function_manager = self._program.getFunctionManager()
        self._address_factory = self._program.getAddressFactory()

        self.signature_libary = None
        self.signatures = None
        self._strings = {}
        self._find_strings()

        start = time.time()
        self._signatures = self._generate()
        end = time.time()

        print("Generated {formal_signatures} formal signatures and {fuzzy_signatures} fuzzy signatures "
              "for {function_count} functions in {duration} seconds."
              .format(formal_signatures=len(self._signatures.formal),
                                            fuzzy_signatures=len(self._signatures.fuzzy),
                                            function_count=len(self._signatures.functions),
                                            duration=(end - start)))
    
    def save(self, signature_file):
        """
        Save Rizzo signatures to the supplied signature file.

        :param signature_file: Full path to save signatures.
        :type signature_file: str
        """
        print("Saving signature to {signature_file}...".format(signature_file=signature_file))
        with open(signature_file, 'wb') as rizz_file:
            pickle.dump(self._signatures, rizz_file)
        print("done.")

    def load(self, signature_file):
        """
        Load Rizzo signatures from a file.

        :param signature_file: Full path to load signatures from.
        :type signature_file: str

        :returns: Loaded signatures
        :rtype: RizzoSignatures
        """
        if not os.path.exists(signature_file):
            raise Exception("Signature file {signature_file} does not exist".format(signature_file=signature_file))

        print("Loading signatures from {signature_file}...".format(signature_file=signature_file))
        with open(signature_file, 'rb') as rizz_file:
            try:
                signatures = pickle.load(rizz_file)
            except:
                print("This does not appear to be a Rizzo signature file.")
                exit(1)
        print("done.")
        return signatures

    def apply(self, signatures):
        """
        Apply signatures to the current program.

        :param signatures: Signatures to apply to current program.
        :type signatures: RizzoSignatures
        """
        rename_count = 0
        signature_matches = self._find_match(signatures)
        renamed = []

        for matches in signature_matches:
            for curr_func, new_func in matches.iteritems():
                addr_hex = hex(curr_func.address)
                if addr_hex.endswith('L'):
                    addr_hex = addr_hex[:-1]
                curr_addr = self._address_factory.getAddress(addr_hex)

                function = self._flat_api.getFunctionAt(curr_addr)
                if function and new_func.name not in renamed:
                    renamed.append(new_func.name)
                    if self._rename_functions(function, new_func.name):
                        rename_count += 1

                duplicates = []
                block_match = {}
                for block in new_func.blocks:
                    new_block = RizzoBlockDescriptor(block)
                    for curr_block in curr_func.blocks:
                        curr_block = RizzoBlockDescriptor(curr_block)

                        if curr_block == new_block:
                            if curr_block in block_match:
                                del block_match[curr_block]
                                duplicates.append(curr_block)
                            elif curr_block not in duplicates:
                                block_match[curr_block] = new_block

                for curr_block, new_block in block_match.iteritems():
                    for curr_function, new_function in \
                            zip(curr_block.functions, new_block.functions):
                        functions = utils.find_function(
                            self._program, curr_function)
                        if len(functions) == 1:
                            if new_function not in renamed:
                                renamed.append(new_function)
                                if self._rename_functions(functions[0],
                                                          new_function):
                                    rename_count += 1

        print("Renamed {function_count} functions.".format(function_count=rename_count))

    def _find_match(self, signatures):
        """
        Find matches to signatures in the current program.

        :param signatures: Signatures to find in current program.
        :type signatures: RizzoSignatures

        :returns: Tuple of matched signatures: (formal, string, immediate, fuzzy)
        :rtype: tuple
        """
        formal_signatures = find_signature_matches(
            signatures.formal, self._signatures.formal, signatures.functions,
            self._signatures.functions, 'formal signatures')

        string_signatures = find_signature_matches(
            signatures.strings, self._signatures.strings, signatures.functions,
            self._signatures.functions, 'string signatures')

        immediate_signatures = find_signature_matches(
            signatures.immediates, self._signatures.immediates,
            signatures.functions, self._signatures.functions,
            'immediate signatures')

        fuzzy_signatures = find_signature_matches(
            signatures.fuzzy, self._signatures.fuzzy, signatures.functions,
            self._signatures.functions, 'fuzzy signatures',
            lambda x, y: len(x.blocks) == len(y.blocks))

        return (formal_signatures, string_signatures, immediate_signatures,
                fuzzy_signatures)

    def _rename_functions(self, function, name):
        """
        Rename a function if the function has not be renamed and new name
        is a valid new function name. Previous renamed are determined by 
        searching for 'FUN_' in the function.

        :param function: Function to be renamed.
        :type function: ghidra.program.model.listing.Function

        :param name: New name to give function.
        :type name: unicode

        :returns: True if function renamed, False for no rename.
        :rtype: bool
        """
        if not function or not name:
            return False

        if 'FUN_' in function.name and 'FUN_' not in name:
            if function:
                print("Renaming {old_function_name} to {new_function_name}"
                      .format(old_function_name=function.name, new_function_name=name))
                function.setName(name, SourceType.USER_DEFINED)
                return True
        elif 'FUN_' not in function.name and 'FUN_' not in name and \
                function.name != name:
            print("Found match with {old_function_name} to {new_function_name} but did not rename."
                  .format(old_function_name=function.name, new_function_name=name))
        return False

    def _signature_hash(self, value):
        """
        Simple hash function used to create a signature.

        :param value: Value to hash.
        :type value: variable

        :returns: Signature hash
        :rtype: int
        """
        return hash(str(value)) & 0xFFFFFFFF

    def _find_strings(self):
        """
        Find strings in the current program and create signatures for them.
        """
        memory = self._memory_map.getAllInitializedAddressSet()
        strings = self._flat_api.findStrings(memory, 2, 1, True, True)

        for string in strings:
            addr = string.getAddress()
            value = string.getString(self._memory_map)
            xref = self._flat_api.getReferencesTo(addr)
            self._strings[addr.hashCode()] = RizzoString(addr, value, xref)

    def _get_function_blocks(self, function):
        """
        Get all code blocks in the provided function.

        :param function: Function to get code blocks from.
        :type function: ghidra.program.model.listing.Function

        :returns: List of code blocks.
        :rtype: ghidra.program.model.block.CodeBlock
        """
        blocks = []
        code_blocks = self._simple_blk.getCodeBlocksContaining(function.body,
                                                               self._monitor)

        while code_blocks.hasNext():
            blocks.append(code_blocks.next())

        return blocks

    def _hash_block(self, block):
        """
        Create signatures for the provided code block.

        :returns: Tuple of formal, fuzzy, function, and immediate signatures)
        """
        formal = []
        fuzzy = []
        functions = []
        immediates = []

        min_addr = block.minAddress
        max_addr = block.maxAddress

        curr_ins = self._flat_api.getInstructionAt(min_addr)

        while curr_ins and curr_ins.getAddress() < max_addr:
            code_ref = []
            data_ref = []

            # Create code and data reference signatures.
            references = curr_ins.getReferencesFrom()
            for reference in references:
                # Don't care about tracking stack references.
                if reference.isStackReference():
                    continue

                if is_code_ref(reference):
                    code_ref.append(reference)

                # Get data reads only if they are to valid memory.
                elif is_data_ref(reference) and \
                        self._memory_map.contains(reference.toAddress):
                    data_ref.append(reference)

            # Append the mnemonic string to the formal signature.
            formal.append(curr_ins.getMnemonicString())

            # If its a call instruction add the function call to the functions
            # signature and make note of the call in the fuzzy signature.
            if is_call_instruction(curr_ins):
                for cref in code_ref:
                    func = self._flat_api.getFunctionAt(cref.toAddress)
                    if func:
                        functions.append(func.getName())
                        fuzzy.append('funcref')
            # Make not of any data references.
            elif data_ref:
                for dref in data_ref:
                    addr_hash = dref.toAddress.hashCode()

                    if self._strings.has_key(addr_hash):
                        string_value = self._strings[addr_hash].value
                    else:
                        string_value = 'dataref'

                    formal.append(string_value)
                    fuzzy.append(string_value)
            # If not data or code then add everything to the formal signature.
            elif not data_ref and not code_ref:
                for i in range(0, curr_ins.getNumOperands()):
                    operand = curr_ins.getDefaultOperandRepresentation(i)
                    formal.append(operand)

                    op_type = curr_ins.getOperandRefType(i)
                    if op_type and op_type.isData():
                        # Indeterminate return values. Just put a try/except
                        # around it so the getValue AttributeError can be
                        # ignored. Not worth checking for types since those
                        # may come and go.
                        try:
                            op_value = curr_ins.getOpObjects(i)[0].getValue()
                            if op_value > 0xFFFF:
                                fuzzy.append(str(op_value))
                                immediates.append(op_value)
                        except (AttributeError, IndexError):
                            pass

            curr_ins = curr_ins.getNext()

        formal_sig = self._signature_hash(''.join(formal))
        fuzzy_sig = self._signature_hash(''.join(fuzzy))

        return (formal_sig, fuzzy_sig, immediates, functions)

    def _hash_function(self, function):
        """
        Create a block by block signature for the provided function.

        :param function: Function to create signature hash for.
        :type function: ghidra.program.model.listing.Function

        :returns: List of signatures per block found.
        """
        block_hash = []

        func_blocks = self._get_function_blocks(function)
        for block in func_blocks:
            block_hash.append(self._hash_block(block))

        return block_hash

    def _generate(self):
        """
        Create signatures for the current program.
        """
        signatures = RizzoSignature()

        # String based signatures
        for (str_hash, curr_string) in self._strings.iteritems():
            # Only create signatures on reasonably long strings with one ref.
            if len(curr_string.value) >= 8 and len(curr_string.xrefs) == 1:
                function = self._flat_api.getFunctionContaining(
                    curr_string.xrefs[0].fromAddress)
                if function:
                    string_hash = self._signature_hash(curr_string.value)
                    entry = utils.address_to_int(function.getEntryPoint())
                    signatures.add_string(string_hash, entry)

        # Formal, fuzzy, and immediate-based function signatures
        for function in self._function_manager.getFunctions(True):
            hashed_function_blocks = self._hash_function(function)

            formal = self._signature_hash(
                ''.join([str(e) for (e, _, _, _) in hashed_function_blocks]))
            fuzzy = self._signature_hash(
                ''.join([str(f) for (_, f, _, _) in hashed_function_blocks]))
            immediate = [str(i) for (_, _, i, _) in hashed_function_blocks]

            function_entry = utils.address_to_int(function.getEntryPoint())
            signatures.functions[function_entry] = (
                function.getName(), hashed_function_blocks)

            signatures.add_formal(formal, function_entry)
            signatures.add_fuzzy(fuzzy, function_entry)

            for value in immediate:
                signatures.add_immediate(value, function_entry)

        signatures.reset_dups()

        return signatures

    def load_signature_library(self, signature_library_file):
        """
        Load Rizzo signatures from a file into the library variable.

        :param signature_library_file: Full path to load signature library from.
        :type signature_library_file: str

        :returns: None
        :rtype: None
        """
        if not os.path.exists(signature_library_file):
            raise Exception("Signature file {signature_library_file} does not exist".format(signature_library_file=signature_library_file))

        print("Loading signature library from {signature_library_file}...".format(signature_library_file=signature_library_file))
        with open(signature_library_file, 'rb') as library_file:
            try:
                self.signature_libary = pickle.load(library_file)
            except:
                print("This does not appear to be a Rizzo signature file.")
                exit(1)
        print("done.")

    def add_current_program_to_library(self):
        formal_count_before_load = len(self.signature_libary.formal)
        fuzzy_count_before_load = len(self.signature_libary.fuzzy)
        strings_count_before_load = len(self.signature_libary.strings)
        functions_count_before_load = len(self.signature_libary.functions)
        immediates_count_before_load = len(self.signature_libary.immediates)
        formaldups_count_before_load = len(self.signature_libary.formaldups)
        fuzzydups_count_before_load = len(self.signature_libary.fuzzydups)
        stringdups_count_before_load = len(self.signature_libary.stringdups)
        functiondups_count_before_load = len(self.signature_libary.functiondups)
        immediatedups_count_before_load = len(self.signature_libary.immediatedups)

        for signature, address in self._signatures.formal.items():
            self.signature_libary.add_formal(signature, address)
        
        for signature, address in self._signatures.fuzzy.items():
            self.signature_libary.add_fuzzy(signature, address)

        for signature, address in self._signatures.strings.items():
            self.signature_libary.add_string(signature, address)

        for signature, address in self._signatures.functions.items():
            self.signature_libary.add_function(signature, address)

        for signature, address in self._signatures.immediates.items():
            self.signature_libary.add_immediate(signature, address)

        formal_count_after_load = len(self.signature_libary.formal)
        fuzzy_count_after_load = len(self.signature_libary.fuzzy)
        strings_count_after_load = len(self.signature_libary.strings)
        functions_count_after_load = len(self.signature_libary.functions)
        immediates_count_after_load = len(self.signature_libary.immediates)
        formaldups_count_after_load = len(self.signature_libary.formaldups)
        fuzzydups_count_after_load = len(self.signature_libary.fuzzydups)
        stringdups_count_after_load = len(self.signature_libary.stringdups)
        functiondups_count_after_load = len(self.signature_libary.functiondups)
        immediatedups_count_after_load = len(self.signature_libary.immediatedups)

        output_str = "Done! Library Change Statistics:\n" \
                     "\t\t\t\tOld\tNew\n" \
                     "Formal:\t\t{formal_before}\t{formal_after}\n" \
                     "Fuzzy:\t\t{fuzzy_before}\t{fuzzy_after}\n" \
                     "String:\t\t{string_before}\t{string_after}\n" \
                     "Function:\t{function_before}\t{function_after}\n" \
                     "Immediate:\t{immediate_before}\t{immediate_after}\n" \
                     "FormalDups:\t\t{formaldups_before}\t{formaldups_after}\n" \
                     "FuzzyDups:\t\t{fuzzydups_before}\t{fuzzydups_after}\n" \
                     "StringDups:\t\t{stringdups_before}\t{stringdups_after}\n" \
                     "FunctionDups:\t{functiondups_before}\t{functiondups_after}\n" \
                     "ImmediateDups:\t{immediatedups_before}\t{immediatedups_after}" \
                     .format(formal_before=formal_count_before_load,
                             formal_after=formal_count_after_load,
                             fuzzy_before=fuzzy_count_before_load,
                             fuzzy_after=fuzzy_count_after_load,
                             string_before=strings_count_before_load,
                             string_after=strings_count_after_load,
                             function_before=functions_count_before_load,
                             function_after=functions_count_after_load,
                             immediate_before=immediates_count_before_load,
                             immediate_after=immediates_count_after_load,
                             formaldups_before=formaldups_count_before_load,
                             formaldups_after=formaldups_count_after_load,
                             fuzzydups_before=fuzzydups_count_before_load,
                             fuzzydups_after=fuzzydups_count_after_load,
                             stringdups_before=stringdups_count_before_load,
                             stringdups_after=stringdups_count_after_load,
                             functiondups_before=functiondups_count_before_load,
                             functiondups_after=functiondups_count_after_load,
                             immediatedups_before=immediatedups_count_before_load,
                             immediatedups_after=immediatedups_count_after_load)

        print(output_str)
    
    def save_signature_library(self, signature_library_file):
        """
        Save Rizzo signature library to the supplied signature file.

        :param signature_file: Full path to save signatures.
        :type signature_file: str
        """
        print("Saving signature to {signature_library_file}...".format(signature_library_file=signature_library_file))
        with open(signature_library_file, 'wb') as library_file:
            pickle.dump(self.signature_libary, library_file)
        print("done.")