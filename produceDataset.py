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


def combine(directory):
    '''
    iterate over files in the specified directory and load the information from each file

    :param directory: directory to walk for analysis
    :return: detection results (a list of dicts)
    '''
    listMalware = []
    #list_len =0
    for root, dirs, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            #print(filepath)
            if Path(filepath).exists():
                with open(filepath, "r") as outfile:
                    readlist = json.load(outfile)
                    #list_len = list_len + len(readlist)
                    listMalware.extend(readlist)
    print(len(listMalware))
    #print(list_len)
    return listMalware


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


def split_and_retain_alpha(input_string):
    '''
    Use a regular expression to split by non-alphanumeric characters
    Filter out substrings that are not alphabetic

    :param input_string: string being split up to substrings that will be filtered
    :return: substrings
    '''
    # Use a regular expression to split by non-alphanumeric characters
    substrings = re.split(r'[^a-zA-Z0-9]+', input_string.lower())

    # Filter out substrings that are not alphabetic
    result = [substring for substring in substrings if substring.isalpha() and len(substring) > 2]

    return result


def similarity_rate(str1, str2):
    '''
    calculate a similarity rate for two strings
    :param s1: str1 to compare
    :param s2: str2 to compare
    :return: similarity rate
    '''
    return SequenceMatcher(None, str1, str2).ratio()


def filter_dict_by_num(sorted_dict, num_sample):
    '''
    reserve the malware families with number of samples over threshold
    :param sorted_dict: key is sub families, value is the number of samples belonging to it
    :param threshold: filter number
    :return:
    '''
    # Use a dictionary comprehension to filter items based on the threshold
    filtered_dict = {key: value for key, value in sorted_dict.items() if value > num_sample}
    return filtered_dict


def filter_common_family(filtered_dict):
    '''
    reserve common malware families while removing the rest
    :param filtered_dict: malware sub families (family1, family2) over threshold samples
    :return: common malware sub families
    '''
    com_mal_family = ['trojan', 'adware', 'expiro', 'ransom', 'pua', 'worm', 'virus', 'backdoor', 'razy', 'outbrowse',
                      'loadmoney', 'shodi', 'ransom', 'miner', 'ngioweb', 'tsunami', 'gafgyt', 'mirai', 'wabot']
    filtered_family = {key:value for key, value in filtered_dict.items() if key[0] in com_mal_family or key[1] in com_mal_family}
    return filtered_family


def replace_similar_strings(strings, threshold=1.0):
    '''
    Find similar keys in a dict and add its value to the shortest key
    :param strings: the dict, key:malware family, value: number of samples
    :param threshold: threshold for similarity rate
    :return: new dict
    '''
    keys = list(strings.keys())
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            if keys[i] in strings and keys[j] in strings:
                #checking the starting character and replacing the similar string with shorter string
                if keys[i][0] == keys[j][0] and similarity_rate(keys[i], keys[j]) > threshold:
                    # Replace with the shorter string
                    if len(keys[i]) < len(keys[j]):
                        strings[keys[i]] = strings.pop(keys[j]) + strings[keys[i]]
                    else:
                        strings[keys[j]] = strings.pop(keys[i]) + strings[keys[j]]

    return strings


def replace_combine_similar_strings(dict, filtereddir, threshold=1.0):
    '''
    replace malware sub families with the longer string by the shorter one
    if they have a similarity rate above the threshold and move the malware samples in the longer one to the shorter one

    :param dict: filtered dict
    :param filtereddir: directory that saves the filtered samples
    :param threshold: threshold for similarity rate
    :return: replaced lists
    '''
    keys = list(dict.keys())

    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            if keys[i] in dict and keys[j] in dict and len(keys[i]) == len(keys[j]):
                if keys[i][0][0] == keys[j][0][0] and similarity_rate(keys[i][0], keys[j][0]) > threshold and keys[i][1] == keys[j][1]:
                        # change the number of samples and move the malware samples to sub families with shorter name
                        if len(keys[i][0]) <= len(keys[j][0]):
                            dict[keys[i]] = dict.pop(keys[j]) + dict[keys[i]]
                            srcdirectory = filtereddir + '/' + '_'.join(keys[j])
                            desdirectory = filtereddir + '/' + '_'.join(keys[i])
                            move_files(srcdirectory, desdirectory)
                            try:
                                # Use shutil.rmtree to delete the src directory as its samples have moved to the new directory
                                shutil.rmtree(srcdirectory)
                                print(f"Directory '{srcdirectory}' deleted successfully.")
                            except FileNotFoundError:
                                print(f"Directory '{srcdirectory}' not found.")
                            except Exception as e:
                                print(f"An error occurred: {e}")

                        else:
                            dict[keys[j]] = dict.pop(keys[i]) + dict[keys[j]]
                            srcdirectory = filtereddir + '/' + '_'.join(keys[i])
                            desdirectory = filtereddir + '/' + '_'.join(keys[j])
                            move_files(srcdirectory, desdirectory)
                            try:
                                #Use shutil.rmtree to delete the src directory as its samples have moved to the new directory
                                shutil.rmtree(srcdirectory)
                                print(f"Directory '{srcdirectory}' deleted successfully.")
                            except FileNotFoundError:
                                print(f"Directory '{srcdirectory}' not found.")
                            except Exception as e:
                                print(f"An error occurred: {e}")

    return dict


def move_files(source_directory, destination_directory, file_extension=None):
    '''
    move files from source directory to destination directory
    :param source_directory:
    :param destination_directory:
    :param file_extension:
    :return: success or not
    '''
    # Ensure the source and destination directories exist
    if not os.path.exists(source_directory):
        print(f"Source directory '{source_directory}' does not exist.")
        return

    if not os.path.exists(destination_directory):
        os.makedirs(destination_directory)

    # List files in the source directory
    files_to_move = os.listdir(source_directory)

    # Optional: Filter files based on file extension
    if file_extension:
        files_to_move = [file for file in files_to_move if file.endswith(file_extension)]

    # Move each file to the destination directory
    for file in files_to_move:
        source_path = os.path.join(source_directory, file)
        destination_path = os.path.join(destination_directory, file)
        shutil.move(source_path, destination_path)
        print(f"Moved '{file}' to '{destination_directory}'.")
    return True


def move_files_from_subfolders(source_folder, destination_folder):
    # Iterate through subdirectories in the source folder
    for root, dirs, files in os.walk(source_folder):
        for subdirectory in dirs:
            subdirectory_path = os.path.join(root, subdirectory)

            # Check if the subdirectory is not empty
            if os.listdir(subdirectory_path):
                # Iterate through files in the subdirectory
                for filename in os.listdir(subdirectory_path):
                    source_filepath = os.path.join(subdirectory_path, filename)
                    destination_filepath = os.path.join(destination_folder, filename)

                    # Move the file to the destination folder
                    shutil.move(source_filepath, destination_filepath)

                    print(f"Moved '{filename}' to '{destination_filepath}'.")
            else:
                print(f"Skipping empty subdirectory: '{subdirectory_path}'.")
                shutil.rmtree(subdirectory_path)
                print(f"Empty Directory '{subdirectory_path}' deleted successfully.")


    return True


def countOccurAllByTopN(listMalware, top_n, malware_family, in_mal_dir, out_mal_class,  threshold=1.0, filter_num=90):
    '''
    Get the top n families for all malware
    Get the top n subfamilies for all malware

    :param listMalware: a list of dicts with each being related to one malware
    :param top_n: the malware families within the n-highest frequencies
    :param malware_family: csv path to write malware families, with each malware saving the top n
    :param in_mal_dir: directory to malware samples
    :param out_mal_class: directory to malware samples in their corresponding subfamilies
    :param threshold: replace_similar_strings(sorted_family_top_ns, threshold), similarity rate threshold
    :param filter_num: filter the subfamilies with number of sample above filter_num
    :return filtered_dict: filtered malware subfamilies, key: malware subfamilies, value:num_samples
    '''
    # save the top n families for all malware
    family_top_ns = []
    # save the top n subfamilies for all malware
    top_sub_family = []
    # iterating malware
    for i in range(len(listMalware)):
        list_malware_families = []
        # iterating engines
        for engine in listMalware[i]["engine_detected"].keys():
            #obtain the classification information for an engine
            if listMalware[i]["engine_detected"][engine]["result"]:
                categorization = split_and_retain_alpha(listMalware[i]["engine_detected"][engine]["result"])
                # save the detection result for each malware
                list_malware_families.extend(categorization)
        #sort strings and use them as its potential classification
        counts = Counter(list_malware_families)
        sorted_malfamilies = dict(sorted(counts.items(), key=lambda item: item[1], reverse=True))
        # Create a new dictionary excluding keys containing 'gen'
        sorted_malfamilies = {k: v for k, v in sorted_malfamilies.items() if 'gen' not in k and 'malicious' not in k and 'malware' not in k and 'application' not in k and 'variant' not in k and 'unwanted' not in k}

        # for each of the malware, we just save the n highest strings as its family
        for key, _ in list(sorted_malfamilies.items())[:top_n]:
            family_top_ns.append(key)

        '''
          sometimes, malware may be classified to two families
          combine them as (0, 1), (0, 2),...
          If the malware is not detected by many engines, it may not have two families
        '''
        sub_family = []  # get sub family (Trojan, Unruy)
        for fam in range(1, top_n):
            if fam > len(list(sorted_malfamilies.items())[:top_n]) - 1:
                break
            sub_family.append(sorted([list(sorted_malfamilies.keys())[0], list(sorted_malfamilies.keys())[fam]]))
        #save the potential sub families
        top_sub_family.extend(sub_family)

        '''
        move malware samples to their corresponding subfamilies
        '''
        malfilepath = in_mal_dir + '/' + listMalware[i]["name"]
        out_mal_dir = out_mal_class + '/' + '_'.join(top_sub_family[-1])
        # print(outpath)
        if not os.path.exists(out_mal_dir):
            os.makedirs(out_mal_dir)

        if not os.path.exists(malfilepath):
            print("there is no such malware")
        else:
            out_mal_path = out_mal_dir + '/' + listMalware[i]["name"]
            shutil.move(malfilepath, out_mal_path)


    '''
    sorted the malware families (each malware belonging to one family) 
    write it out to a csv file
    '''

    counts_family_top_ns = Counter(family_top_ns)
    sorted_family_top_ns = dict(sorted(counts_family_top_ns.items(), key=lambda item: len(item[0]), reverse=True))
    sorted_family_top_ns = replace_similar_strings(sorted_family_top_ns, threshold)
    sorted_family_top_ns = dict(sorted(sorted_family_top_ns.items(), key=lambda item: item[1], reverse=True))
    with open(malware_family, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        # Write header
        csv_writer.writerow(["Name", "Count"])
        # Write data
        for key, value in sorted_family_top_ns.items():
            csv_writer.writerow([key, value])

    '''
    sorted the malware subfamilies (each malware belonging to up to n families) 
    write it out to a csv file
    '''
    #the number of malware samples
    print(len(top_sub_family))
    #sort the malware subfamilies and preserve malware families above 90 samples
    counts_sub_fam = Counter(map(tuple, top_sub_family))
    sorted_counts_sub_fam = dict(sorted(counts_sub_fam.items(), key=lambda item: item[1], reverse=True))
    filtered_dict = filter_dict_by_num(sorted_counts_sub_fam, filter_num)

    return filtered_dict


def classify(filtered_dict, srcdir, filtereddir, com_fam_dir =r'com_fam_dir', com_familycsv='com_family.csv', filtercsv=r'filter.csv', replacedcsv=r'replaced.csv', threshold=0.7):

    '''
    :param filtered_dict: only malware subfamilies above num_samples
    :param srcdir:
    :param filtereddir:
    :param filtercsv:
    :param replacedcsv:
    :param threshold:
    :return:
    '''
    #write the information out to filtercsv, including filtered malware subfamilies, number of samples
    with open(filtercsv, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        # Write header
        csv_writer.writerow(["Name", "Count"])
        # Write data
        for sub_fam, freq in filtered_dict.items():
            csv_writer.writerow([sub_fam, freq])


    #only move the filtered malware samples from source directory that includes all malware subfamilies to filtered directory
    #srcdir should the top directory, key is the malware subfamily name that we want to move
    for key, _ in filtered_dict.items():
        srcpath = srcdir + '/' + '_'.join(key)
        outpath = filtereddir + '/' + '_'.join(key)
        move_files(srcpath, outpath)


    #replace the similar strings and combine their malware samples
    replaced_sorted_counts = dict(sorted(replace_combine_similar_strings(filtered_dict, filtereddir, threshold).items(), key=lambda item: item[1], reverse=True))
    #replacedcsv saves the combined malware samples in their subfamilies
    with open(replacedcsv, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        # Write header
        csv_writer.writerow(["Name", "Count"])
        # Write data
        for sub_fam, freq in replaced_sorted_counts.items():
            csv_writer.writerow([sub_fam, freq])

    #only reserve the popular malware subfamilies and move them to com_fam_dir
    common_family = filter_common_family(replaced_sorted_counts)

    for key, value in common_family.items():
        srcpath = filtereddir + '/' + '_'.join(key)
        despath = com_fam_dir + '/' +'_'.join(key)
        move_files(srcpath, despath)

    with open(com_familycsv, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        # Write header
        csv_writer.writerow(["Name", "Count"])
        # Write data
        for sub_fam, freq in common_family.items():
            csv_writer.writerow([sub_fam, freq])

    return common_family


def clearemptyfolder(source_folder):
    for root, dirs, files in os.walk(source_folder):
        for subdirectory in dirs:
            subdirectory_path = os.path.join(root, subdirectory)
            if not os.listdir(subdirectory_path):
                shutil.rmtree(subdirectory_path)

def rollback(com_fam_dir, filtered_dir, out_mal_class, in_mal_dir):
    move_files_from_subfolders(com_fam_dir, in_mal_dir)
    move_files_from_subfolders(out_mal_class, in_mal_dir)
    move_files_from_subfolders(filtered_dir, in_mal_dir)
    clearemptyfolder(filtered_dir)
    clearemptyfolder(out_mal_class)

def dataset():
    '''
    create our dataset for classification
    :return:
    '''

    vtreport = r'winreports.json'
    listMalware = readreport(vtreport)
    top_n = 2
    malware_family = r"malfam_topn.csv"
    in_mal_dir = r'./WindowsMalware'
    out_mal_class = r'./WindowsFamily'
    threshold = 1.0
    filter_num = 90
    filtered_dict = countOccurAllByTopN(listMalware, top_n, malware_family, in_mal_dir, out_mal_class, threshold, filter_num)
    srcdir = r'./WindowsFamily'
    filtered_dir = r'MalwareFilter'
    com_fam_dir = r'com_fam_dir_win'
    com_familycsv = 'com_family_win.csv'
    filtercsv = r'filterwin.csv'
    replacedcsv = r'replacedwin.csv'
    classify(filtered_dict, srcdir, filtered_dir, com_fam_dir, com_familycsv, filtercsv, replacedcsv)

def linuxdataset():
        '''
        create our dataset for classification
        :return:
        '''
        directory = r'../linuxreports'
        listMalware = combine(directory)
        top_n = 2
        malware_family = r"linuxfam_topn.csv"
        in_mal_dir = r'../LinuxMalware'
        out_mal_class = r'../LinuxFamily'
        threshold = 1.0
        filter_num = 35
        filtered_dict = countOccurAllByTopN(listMalware, top_n, malware_family, in_mal_dir, out_mal_class, threshold,
                                            filter_num)
        srcdir = r'../LinuxFamily'
        filtered_dir = r'../LinuxFilter'
        classify(filtered_dict, srcdir, filtered_dir)

def androiddataset():
    '''
     create our dataset for classification
     :return:
     '''
    directory = r'../androidreports'
    listMalware = combine(directory)
    top_n = 2
    malware_family = r"androidfam_topn.csv"
    in_mal_dir = r'../AndroidMalware'
    out_mal_class = r'../AndroidFamily'
    threshold = 1.0
    filter_num = 35
    filtered_dict = countOccurAllByTopN(listMalware, top_n, malware_family, in_mal_dir, out_mal_class, threshold,
                                        filter_num)
    srcdir = r'../AndroidFamily'
    filtered_dir = r'../AndroidFilter'
    classify(filtered_dict, srcdir, filtered_dir)

def backtoorigin():
    '''
    collect all malware back to the original folder
    :return:
    '''
    com_fam_dir = r'./WindowsFamily'
    filtered_dir = r'./MalwareFilter'
    out_mal_class = r'./com_fam_dir_win'
    in_mal_dir = r'./WindowsMalware'
    rollback(com_fam_dir, filtered_dir, out_mal_class, in_mal_dir)


def backtooriginlinux():
    '''
    collect all malware back to the original folder
    :return:
    '''
    com_fam_dir = r'./com_fam_dir_linux'
    filtered_dir = r'../LinuxFilter'
    out_mal_class = r'../LinuxFamily'
    in_mal_dir = r'../LinuxMalware'
    rollback(com_fam_dir, filtered_dir, out_mal_class, in_mal_dir)


def backtooriginandroid():
    '''
    collect all malware back to the original folder
    :return:
    '''
    com_fam_dir = r'./com_fam_dir_android'
    filtered_dir = r'../AndroidFilter'
    out_mal_class = r'../AndroidFamily'
    in_mal_dir = r'../AndroidMalware'
    rollback(com_fam_dir, filtered_dir, out_mal_class, in_mal_dir)

#dataset()
backtoorigin()

#linuxdataset()
#backtooriginlinux()
#androiddataset()

#move_files_from_subfolders(r'../AndroidMalware', r'../AndroidMalware')

#print(similarity_rate(r'gen', 'generic'))

#print(similarity_rate(r'ransom', 'ransomgen'))





