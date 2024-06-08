from PIL import Image
import numpy as np
import os
from pathlib import Path
import math
import cv2
from collections import Counter
import pandas as pd
import time

def get_file_size(file_path):
    # Get the file size in bytes
    size_bytes = os.stat(file_path).st_size
    return size_bytes


def readbinary(file_path):
    try:
        with open(file_path, 'rb') as file:
            # Read the entire file into a binary variable
            binary_data = file.read()

    except FileNotFoundError:
        print(f'The file "{file_path}" was not found.')

    except Exception as e:
        print(f'An error occurred: {e}')
    return binary_data

def getImgHeight(filesize):
    kb = 1024
    # Example usage:
    file_size_ranges = {
        (0, 10*kb): 32,
        (10*kb, 30*kb): 64,
        (30*kb, 60*kb): 128,
        (60*kb, 100*kb): 256,
        (100*kb, 200*kb): 384,
        (200*kb, 500*kb): 512,
        (500*kb, 1000*kb): 768,
        (1000*kb, 2000*kb): 1024,
        (2000*kb, 5000*kb): 1536,
        (5000*kb, 100000000000*kb): 2048,
    }
    for size_range, width in file_size_ranges.items():
        start, end = size_range
        if start <= filesize <= end:
            return width
    print("no range is found")


def binToImgSingleDir(srcdir):

        for filename in os.listdir(srcdir):

            filepath = os.path.join(srcdir, filename)
            if Path(filepath).exists():
                filesize = get_file_size(filepath)
                height = getImgHeight(filesize)
                binary_data = readbinary(filepath)
                byte_array = np.frombuffer(binary_data, dtype=np.uint8)
                width = len(byte_array) // (height)
                # Adjust dimensions if needed
                byte_array = byte_array[:width * height]

                image_array = byte_array.reshape((height, width))
                image = Image.fromarray(image_array)
                outdir = srcdir+'img/'
                if not Path(outdir).exists():
                    os.makedirs(outdir)
                image.save(outdir + filename+'.png')


def binToImg(srcdir, outdir):
    if not os.path.exists(outdir):
        os.makedirs(outdir)

    for root, dirs, files in os.walk(srcdir):
        for subdirectory in dirs:
            subdirectory_path = os.path.join(root, subdirectory)
            destination_dir = os.path.join(outdir, subdirectory)
            # Check if the subdirectory is not empty
            if os.listdir(subdirectory_path):
                # Iterate through files in the subdirectory
                for filename in os.listdir(subdirectory_path):
                    source_filepath = os.path.join(subdirectory_path, filename)
                    if Path(source_filepath).exists():
                        filesize = get_file_size(source_filepath)
                        height = getImgHeight(filesize)
                        binary_data = readbinary(source_filepath)
                        byte_array = np.frombuffer(binary_data, dtype=np.uint8)
                        width = len(byte_array) // height
                        # Adjust dimensions if needed
                        byte_array = byte_array[:width * height]

                        image_array = byte_array.reshape((height, width))
                        image = Image.fromarray(image_array)
                        if not Path(destination_dir).exists():
                            os.makedirs(destination_dir)
                        image.save(destination_dir + '/' + filename + '.png')


def bin2image(srcdir):
    for root, dirs, files in os.walk(srcdir):
        for subdirectory in dirs:
            subdirectory_path = os.path.join(root, subdirectory)
            # Check if the subdirectory is not empty
            if os.listdir(subdirectory_path):
                # Iterate through files in the subdirectory
                for filename in os.listdir(subdirectory_path):
                    source_filepath = os.path.join(subdirectory_path, filename)
                    if Path(source_filepath).exists():
                        saved_image = Image.open(source_filepath)
                        print(np.array(saved_image).shape)

def readcsv():
    batch = pd.read_csv(r'program_info.csv')
    column1_values = batch['Function']
    column2_values = batch['Block']
    column3_values = batch['Instruction']
    counter1 = Counter(column1_values)
    counter2 = Counter(column2_values)
    counter3 = Counter(column3_values)
    sorted_counter1 = dict(sorted(counter1.items(), key=lambda x:x[1], reverse=True))
    sorted_counter2 = dict(sorted(counter2.items(), key=lambda x: x[1], reverse=True))
    sorted_counter3 = dict(sorted(counter3.items(), key=lambda x: x[1], reverse=True))
    largest_value1 = next(iter(sorted_counter1.values()))
    largest_value2 = next(iter(sorted_counter2.values()))
    largest_value3 = next(iter(sorted_counter3.values()))
    print(largest_value1)
    print(largest_value2)
    print(largest_value3)

