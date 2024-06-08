import json
import argparse
import os
import pyzipper
from pathlib import Path
import re
from collections import Counter
import csv
from difflib import SequenceMatcher
import Levenshtein
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import shutil
import cv2
import numpy as np
import angr


def getInfo(filepath):
    project = angr.Project(filepath, auto_load_libs=False)
    cfg = project.analyses.CFGFast()

    list_instr=[]
    list_block=[]
    list_func=[]

    for function in cfg.kb.functions.values():
        if not function.name.startswith('_') and function.size > 0:
            print(function.name)
            print(f"Function {hex(function.addr)}:")
            print(f"  Size: {function.size} bytes")
            list_func.append(function.size)
            #print(f"  Basic Block Sizes:")
            for block_addr in function.block_addrs:
                block = project.factory.block(block_addr)
                print(f"    Block {hex(block.addr)}: {block.size} bytes")
                list_block.append(block.size)
                for ins in block.capstone.insns:
                    list_instr.append(len(ins.bytes))
    return list_func, list_block, list_instr


def iter_samples(dataset_dir):
    '''


    :param dataset_dir:
    :return:
    '''
    '''
        for root, dirs, files in os.walk(dataset_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
    '''
    func_info = []
    block_info = []
    instr_info = []
    for root, dirs, files in os.walk(dataset_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            if Path(filepath).exists():
                list_func, list_block, list_instr = getInfo(filepath)
                func_info.extend(list_func)
                block_info.extend(list_block)
                instr_info.extend(list_instr)

    avg_func = np.mean(func_info)
    print(f"      Function mean: {avg_func} bytes")
    median_func = np.median(func_info)
    print(f"      Function median: {median_func} bytes")
    max_func = np.max(func_info)
    print(f"      Function max: {max_func} bytes")
    min_func = np.min(func_info)
    print(f"      Function min: {min_func} bytes")
    func_counter = Counter(func_info)
    sorted_function = sorted(func_counter.items(), key=lambda x: x[1], reverse=True)
    # Get the key with the highest value (the mode)
    mode_func = sorted_function[0][0]
    print("Mode func:", mode_func)

    avg_block = np.mean(block_info)
    print(f"      Block mean: {avg_block} bytes")
    median_block = np.median(block_info)
    print(f"      Block median: {median_block} bytes")
    max_block = np.max(block_info)
    print(f"      Block max: {max_block} bytes")
    min_block = np.min(block_info)
    print(f"      Block min: {min_block} bytes")
    block_counter = Counter(block_info)
    sorted_block = sorted(block_counter.items(), key=lambda x: x[1], reverse=True)
    mode_block = sorted_block[0][0]
    print("Mode block:", mode_block)

    avg_instr = np.mean(instr_info)
    print(f"      Instr mean: {avg_instr} bytes")
    median_instr = np.median(instr_info)
    print(f"      Instr median: {median_instr} bytes")
    max_instr = np.max(instr_info)
    print(f"      Instr max: {max_instr} bytes")
    min_instr = np.min(instr_info)
    print(f"      Instr min: {min_instr} bytes")
    instr_counter = Counter(instr_info)
    sorted_instr = sorted(instr_counter.items(), key=lambda x: x[1], reverse=True)
    mode_instr = sorted_instr[0][0]
    print("Mode block:", mode_instr)

    with open(r'program_info_func.csv', 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        # Write data
        csv_writer.writerows(func_info)

    with open(r'program_info_bblock.csv', 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        # Write data
        csv_writer.writerows(block_info)

    with open(r'program_info_instr.csv', 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        # Write data
        csv_writer.writerows(instr_info)


iter_samples(r'../dataset')









