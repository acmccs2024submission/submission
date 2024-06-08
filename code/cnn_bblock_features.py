import angr
import hashlib
import numpy as np
from PIL import Image
from pathlib import Path
import os
import time
import r2pipe


def getInfo_re(filepath):

    # Open the binary in radare2
    r2 = r2pipe.open(filepath)
    r2.cmd('aaa')  # Perform full analysis

    # Get all functions
    functions = r2.cmdj('aflj')
    image_matrix = []
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
                opcodes_in_block.append(instr['opcode'].split()[0])
                #print(f"    Instruction: {instr['opcode']} at {hex(instr['offset'])}")
            bb_string=''.join(opcodes_in_block)
            hash_bb = simhash256(bb_string)
            bb_pixels = convert_to_0255(hash_bb)
            image_matrix.append(bb_pixels)

    if image_matrix:
        return image_matrix
    else:
        with open(filepath, 'rb') as file:
            while chunk := file.read(32):
                # Compute the SHA-256 hash of the current chunk
                hash_obj = hashlib.sha256(chunk)
                # Convert the hash to a binary string
                hash_bin = bin(int(hash_obj.hexdigest(), 16))[2:].zfill(256)
                bb_pixels = convert_to_0255(hash_bin)
                image_matrix.append(bb_pixels)
        return image_matrix

#function to iterate functions, basic blocks, instructions and opcodes
def getInfo(filepath):
    project = angr.Project(filepath, auto_load_libs=False)
    cfg = project.analyses.CFGFast()
    image_matrix = []
    for function in cfg.kb.functions.values():
        if not function.name.startswith('_') and function.size > 0:
            for block_addr in function.block_addrs:
                block = project.factory.block(block_addr)
                opcodes_in_block = []
                for ins in block.capstone.insns:
                    #print(f"      Instruction {hex(ins.address)}: {len(ins.bytes)} bytes")
                    #print("------------------------------------")
                    #print(ins.mnemonic)
                    opcodes_in_block.append(ins.mnemonic)
                bb_string=''.join(opcodes_in_block)
                hash_bb = simhash256(bb_string)
                bb_pixels = convert_to_0255(hash_bb)
                image_matrix.append(bb_pixels)
    if image_matrix:
        return image_matrix
    else:
        with open(filepath, 'rb') as file:
            while chunk := file.read(32):
                # Compute the SHA-256 hash of the current chunk
                hash_obj = hashlib.sha256(chunk)
                # Convert the hash to a binary string
                hash_bin = bin(int(hash_obj.hexdigest(), 16))[2:].zfill(256)
                bb_pixels = convert_to_0255(hash_bin)
                image_matrix.append(bb_pixels)
        return image_matrix


#function to iterate every malware sample
def iter_samples(srcdir, outdir):
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
                        image_matrix = getInfo_re(source_filepath)
                    if not Path(destination_dir).exists():
                        os.makedirs(destination_dir)
                    image = Image.fromarray(np.array(image_matrix))
                    image.save(destination_dir + '/' + filename + '.png')
    end_time = time.time()
    execution_time = (end_time - start_time)/25739
    print("Execution time per malware:", execution_time, "seconds")





def simhash256(data):
    # Compute the SHA-256 hash of the input data
    hash_obj = hashlib.sha256(data.encode('utf-8'))
    # Convert the hash to a binary string
    hash_bin = bin(int(hash_obj.hexdigest(), 16))[2:].zfill(256)
    return hash_bin


def convert_to_0255(bit_string):
    # Convert each bit to 0 if it is 0, otherwise convert to 255
    return [0 if bit == '0' else 255 for bit in bit_string]

'''
# Example usage
basic_block = "Example basic block"
hash_bin = simhash256(basic_block)
result = convert_to_0255(hash_bin)

print(f"SimHash256: {hash_bin},{len(hash_bin)}")
print(f"Converted: {result}")
'''
'''
# Example usage:
shreds = ["section of code 1", "section of code 2", "section of code 3"]
x = 22  # Choose the accuracy factor (number of bits to consider from MD5 hash)
feature_hash = create_feature_hash(shreds, x)
print("Feature hash:", feature_hash)
'''
'''
# Example usage:
feature_hash1 = [1, 0, 1, 0, 1]
feature_hash2 = [0, 1, 1, 0, 1]
jaccard = jaccard_index(feature_hash1, feature_hash2)
print("Jaccard Index:", jaccard)
'''

#image_matrix = getInfo("./WindowsFilteredByAngr/generic_worm/VirusShare_1ef41afddd67ed9236a96abced727fa6")
#print(np.array(image_matrix).shape)
iter_samples(r'C:\Users\defaultuser0.DESKTOP-931HL80\Desktop\Montana_State_University\2024-summer\revise_paper\partial_samples', r'./WindowsMalware')

#getInfo_re(r'C:\Users\defaultuser0.DESKTOP-931HL80\Desktop\Montana_State_University\2024-summer\revise_paper\partial_samples\pua_softpulse\VirusShare_0c6a45d7f0ae4a607e07b6a7d7a99c86')