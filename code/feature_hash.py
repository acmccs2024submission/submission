import re
import angr
import hashlib
import numpy as np
from PIL import Image
from pathlib import Path
import os
import time
import zlib
import r2pipe
# Define patterns for replacements

# Define patterns for replacements
registers = r'\b(eax|ebx|ecx|edx|esi|edi|esp|ebp|rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r8|r9|r10|r11|r12|r13|r14|r15)\b'
locations = r'\bloc_[0-9A-Fa-f]+\b'
constant_memory = r'\b0x[0-9A-Fa-f]{5,}\b'  # Heuristic: consider hex values with 5 or more digits as memory references
constant_values = r'\b(?<!0x)\d+\b|\b0x[0-9A-Fa-f]{1,4}\b'  # Non-address constants and small hex values
variable_references = r'\[\s*(?:REG|\b0x[0-9A-Fa-f]+\b|\d+|\+|-|\*|\s+)+\s*\]'

def replace_registers(instruction):
    registers = set(['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp',
                     'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp', 'r8', 'r9','r10','r11','r12','r13','r14','r15',
                     'ax', 'bx', 'cx', 'dx', 'ah', 'bh', 'ch', 'dh'])
    for reg in registers:
        instruction = re.sub(r'\b' + reg + r'\b', "REG", instruction)
    return instruction


def replace_locations(instruction, mnemonic):
    # Replacing any constant address, place in memory, or constant for jump and call instructions
    if mnemonic.startswith('j') or mnemonic == 'call':
        instruction = re.sub(r'0x[0-9A-Fa-f]+', 'LOC', instruction)
        instruction = re.sub(r'\[.*?\]', 'LOC', instruction)  # Constant memory references
    return instruction


def replace_constant_memory_references(instruction):
    return re.sub(r'\[0x[0-9A-Fa-f]+\]', 'MEM', instruction)

def replace_variable_references(instruction):
    # Assuming variable references are complex memory addresses calculated at runtime
    instruction = re.sub(r'\[.*?\]', 'VAR', instruction)
    return instruction

def replace_constant_values(instruction):
    instruction = re.sub(r'\b\d+\b', 'CONST', instruction)  # Literal numeric values
    instruction = re.sub(r'\b0x[0-9A-Fa-f]+\b', 'CONST', instruction)  # Literal numeric values starting with '0x'
    instruction = re.sub(r'\b\d+h\b', 'CONST', instruction)  # Literal numeric values ending with 'h'
    return instruction


def process_instruction(instruction, mnemonic):
    instruction = replace_registers(instruction)
    instruction = replace_locations(instruction, mnemonic)
    instruction = replace_constant_memory_references(instruction)
    instruction = replace_variable_references(instruction)
    instruction = replace_constant_values(instruction)
    return instruction


def getInfo_re(filepath):

    # Open the binary in radare2
    r2 = r2pipe.open(filepath)
    r2.cmd('aaa')  # Perform full analysis

    # Get all functions
    functions = r2.cmdj('aflj')
    insts = []
    for func in functions:
        print(f"Function: {func['name']} at {hex(func['offset'])}")

        # Get basic blocks in the function
        blocks = r2.cmdj(f"afbj {func['offset']}")
        for block in blocks:
            print(f"  Basic Block: {hex(block['addr'])}")

            # Get instructions in the basic block
            instructions = r2.cmdj(f"pdfj @ {block['addr']}")
            opcodes_in_block = []
            for instr in instructions['ops']:
                replaced_instructions = process_instruction(instr['opcode'], instr['opcode'].split()[0])
                insts.append(replaced_instructions)
    if insts:
        return insts
    else:
        with open(filepath, 'rb') as file:
            while chunk := file.read(24):
                insts.append(chunk)
        return insts

#function to iterate functions, basic blocks, instructions and opcodes
def getInfo(filepath):
    project = angr.Project(filepath, auto_load_libs=False)
    cfg = project.analyses.CFGFast()
    insts = []

    for function in cfg.kb.functions.values():
        if not function.name.startswith('_') and function.size > 0:
            for block_addr in function.block_addrs:
                block = project.factory.block(block_addr)
                for ins in block.capstone.insns:
                    instruction = ins.mnemonic + ' ' + ins.op_str
                    replaced_instructions = process_instruction(instruction, ins.mnemonic)
                    insts.append(replaced_instructions)
    if insts:
        return insts
    else:
        with open(filepath, 'rb') as file:
            while chunk := file.read(24):
                insts.append(chunk)
        return insts


def generate_ngrams(instructions, n):
    return [' '.join(instructions[i:i + n]) for i in range(len(instructions) - n + 1)]


def create_feature_hash(shreds, num_bits):
    """
    Create a feature hash for a list of shreds.

    Parameters:
    - shreds: List of shreds (sections of executable code)
    - x: Accuracy factor

    Returns:
    - Binary feature hash array
    """
    # Calculate the length of the feature hash array
    hash_length = 2 ** num_bits
    # Initialize the feature hash array with zeros
    feature_hash = [0] * hash_length

    # Iterate over each shred
    for shred in shreds:
        # Create an MD5 sum of the current shred
        md5_hash = hashlib.md5(shred.encode()).digest()
        #print(md5_hash)
        # Convert MD5 hash to binary representation
        binary_hash = ''.join(format(byte, '08b') for byte in md5_hash)
        #print(binary_hash)
        # Extract the final num_bits from the binary hash and convert to integer
        index = int(binary_hash[-num_bits:], 2)
        #print(index)
        # Set fh[index] = 1
        feature_hash[index] = 1

    return feature_hash


def compress_feature_hash(feature_hash):
    """
    Compress a list of feature hashes using zlib compression.

    Parameters:
    - feature_hashes: List of feature hashes (numpy arrays)

    Returns:
    - Compressed feature hashes
    """
    # Convert the numpy array to bytes
    byte_hash = bytes(feature_hash)
    #print(byte_hash)
    compressed_hash = zlib.compress(byte_hash)
    return compressed_hash


def decompress_feature_hash(compressed_hash, hash_length):
    """
    Decompress a list of compressed feature hashes using zlib decompression.

    Parameters:
    - compressed_hashes: List of compressed feature hashes
    - hash_length: Length of the uncompressed feature hash arrays

    Returns:
    - Decompressed feature hashes
    """


    # Decompress the compressed hash using zlib
    byte_hash = zlib.decompress(compressed_hash)
    # Convert the bytes back to a numpy array
    hash_array = np.frombuffer(byte_hash, dtype=np.uint8)
    # Resize the hash array to the original length
    hash_array.resize(hash_length)
    return hash_array


def write_compressed_hashes_to_file(compressed_hash, file_path):
    """
    Write compressed feature hashes to a text file.

    Parameters:
    - compressed_hashes: List of compressed feature hashes
    - file_path: Path to the output text file
    """
    with open(file_path, 'w') as f:
        serialized_hash = ','.join(map(str, compressed_hash))
        f.write(serialized_hash)


def jaccard_index(feature_hash1, feature_hash2):
    """
    Compute the Jaccard Index between two feature hash arrays.

    Parameters:
    - feature_hash1: First feature hash array
    - feature_hash2: Second feature hash array

    Returns:
    - Jaccard Index
    """
    # Count the number of common elements (1s)
    intersection = sum(a & b for a, b in zip(feature_hash1, feature_hash2))
    # Count the total number of unique elements (1s)
    union = sum(a | b for a, b in zip(feature_hash1, feature_hash2))
    # Compute the Jaccard Index
    jaccard_index = intersection / union if union > 0 else 0
    return jaccard_index

#function to iterate every malware sample
def iter_samples(srcdir, outdir, n_gram, reserved_bits):
    '''

    :param dataset_dir:
    :return:
    '''
    '''
        for root, dirs, files in os.walk(dataset_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
    '''
    if not os.path.exists(outdir):
        os.makedirs(outdir)
    start_time = time.time()
    for root, dirs, files in os.walk(srcdir):
        for subdirectory in dirs:
            subdirectory_path = os.path.join(root, subdirectory)
            destination_dir = os.path.join(outdir, subdirectory)
            if os.listdir(subdirectory_path):
                # Iterate through files in the subdirectory
                for filename in os.listdir(subdirectory_path):
                    source_filepath = os.path.join(subdirectory_path, filename)
                    if Path(source_filepath).exists():
                        instrs = getInfo_re(source_filepath)
                        n_grams = generate_ngrams(instrs, n_gram)
                        feature_hash = create_feature_hash(n_grams, reserved_bits)
                        #compressed_hash = compress_feature_hash(feature_hash)
                    if not Path(destination_dir).exists():
                        os.makedirs(destination_dir)
                    write_compressed_hashes_to_file(feature_hash, destination_dir + '/' + filename + '1.txt')
    end_time = time.time()
    execution_time = (end_time - start_time)/25739
    print("Execution time per malware:", execution_time, "seconds")


iter_samples(r'../dataset', r'./feature_hash', 4, 22)
