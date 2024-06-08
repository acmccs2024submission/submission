import json
from pathlib import Path
import os
import csv
import numpy as np


def iterate_files(root_folder):
    filenames_list = []

    for dirpath, dirnames, filenames in os.walk(root_folder):
        for filename in filenames:
            filenames_list.append(filename.split('.')[0])
    return filenames_list

def readreport(filepath):
    '''
    load the virustotal report information from the specified file

    :param filepath: filepath to load
    :return: detection results (a list of dicts)
    '''
    listMalware = []
    if Path(filepath).exists():
        with open(filepath, "r") as outfile:
                listMalware = json.load(outfile)
    else:
        print('virustotal report path not exists!')
    print(len(listMalware))
    return listMalware

def getfilename(directory):
    filenames=[]
    for root, dirs, files in os.walk(directory):
        for file in files:
            filenames.append(file.split('.')[0])

    return filenames


def create_dictionary(directory):
    file_dict = {}
    common_type =['adware', 'trojan', 'virus','pua']
    # Walk through the directory and its subdirectories
    for root, dirs, files in os.walk(directory):
        # Iterate over each file in the current directory
        for file in files:
            # Get the name of the parent subfolder
            parent_folder = os.path.basename(root)
            # Add the filename and its corresponding subfolder name to the dictionary
            if parent_folder.split('_')[0] in common_type:
                file_dict[file.split('.')[0]] = parent_folder.split('_')[1]
            else:
                file_dict[file.split('.')[0]] = parent_folder.split('_')[0]
    #print(file_dict)
    return file_dict



def create_virustotal_dict():
    virustotal_dict={}
    listMalware = readreport(r'ase_dataset.json')
    for virus in listMalware:
        labels=[]
        for engine in virus['engine_detected'].keys():
            if virus['engine_detected'][engine]['result']:
                labels.append(virus['engine_detected'][engine]['result'].lower())
            else:
                labels.append(virus['engine_detected'][engine]['result'])
        virustotal_dict[virus['name']] = labels
    return virustotal_dict


def count_substring_occurrences(substring, string_list):
    # Initialize a counter to store the number of occurrences
    count = 0
    # Iterate over each string in the list
    for string in string_list:
        # Check if the substring is present in the string
        if string:
            if substring in string:
                # If present, increment the counter
                count += 1
    return count

def write_detection_rate():
    file_dict = create_dictionary(r'./ase_dataset')
    virustotal_dict = create_virustotal_dict()
    detection_rate=[]
    for key, value in file_dict.items():#key is filename,value is class
        if key in virustotal_dict.keys():#key is filename, value is label
            print(count_substring_occurrences(file_dict[key], virustotal_dict[key])/len(virustotal_dict[key]))
            detection_rate.append([count_substring_occurrences(file_dict[key], virustotal_dict[key])/len(virustotal_dict[key])])

    output_file_path = "detect_results.csv"
    # Write the data to the CSV file
    with open(output_file_path, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerows(detection_rate)

def getsubfamily(directory):
    filenames=[]
    for root, dirs, files in os.walk(directory):
        for file in files:
            filenames.append(file.split('.')[0])

    return filenames

def classinfo():
    dir = r'ase_dataset/adware_pua'
    virustotal_dict = create_virustotal_dict()
    #test_substrings = ['playtech', 'trojan', 'pua']
    test_substrings =['pua', 'toolbar', 'ad']
    #test_substrings = ['adware', 'trojan', 'startpage']
    playtech_l=[]
    trojan_l = []
    pua_l = []
    for file in os.listdir(dir):
        #print(file.split('.')[0])
        key = file.split('.')[0]
        if key in virustotal_dict.keys():
            playtech_l.append(count_substring_occurrences(test_substrings[0], virustotal_dict[key])/len(virustotal_dict[key]))
            trojan_l.append(count_substring_occurrences(test_substrings[1], virustotal_dict[key])/len(virustotal_dict[key]))
            pua_l.append(count_substring_occurrences(test_substrings[2], virustotal_dict[key])/len(virustotal_dict[key]))
    print(np.mean(playtech_l))
    print(np.mean(trojan_l))
    print(np.mean(pua_l))

classinfo()

