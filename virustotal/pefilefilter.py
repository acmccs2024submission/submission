import pefile
import os
import glob
import shutil


def num_img_fams_list(inp_dir):
  os.chdir(inp_dir)  #the parent fold with sub-folders
  list_fams = os.listdir(os.getcwd()) #vector of strings with family names
  no_imgs = [] # No. of samples per family

  for family in range(len(list_fams)):
     os.chdir(list_fams[family])
     no_per_family = len(glob.glob('*.png'))
     no_imgs.append(no_per_family)
     os.chdir('..')
  return no_imgs, list_fams


"""
filter non-PE files
"""
def is_pe_file(file_path):
    try:
        # Open the file in binary mode
        with open(file_path, 'rb') as file:
            # Create a PE object
            pe = pefile.PE(data=file.read(), fast_load=True)

            # Check if the file is a PE file
            if pe.NT_HEADERS.Signature:
                print(f"{file_path} is a PE file.")
                print(hex(pe.NT_HEADERS.Signature))
                return True
    except pefile.PEFormatError as e:
        print(f"Error: {file_path} - {e}")
        os.remove(file_path)
        print(f"{file_path} removed.")
        return False


"""
move a file to destination_dir
"""
def move_file(source_path, destination_directory):
    try:
        # Check if the source file exists
        if not os.path.exists(source_path):
            print(f"Source file '{source_path}' does not exist.")
            return

        # Create the destination directory if it doesn't exist
        if not os.path.exists(destination_directory):
            os.makedirs(destination_directory)

        # Construct the destination path
        destination_path = os.path.join(destination_directory, os.path.basename(source_path))

        # Move the file
        shutil.move(source_path, destination_path)

        print(f"File '{source_path}' moved to '{destination_path}'.")
    except Exception as e:
        print(f"Error: {e}")

"""
is PE32 or not
"""

def groupFile(file_path, num_pe32=None, num_pe64=None):
   if(is_pe_file(file_path)):
       with open(file_path, 'rb') as file:
           pe = pefile.PE(data=file.read(), fast_load=True)
           if pe.OPTIONAL_HEADER.Magic==pefile.OPTIONAL_HEADER_MAGIC_PE:
               print(hex(pefile.OPTIONAL_HEADER_MAGIC_PE))
               file.close()
               num_pe32 = num_pe32 + 1
               move_file(file_path, r'C:/Users/defaultuser0.DESKTOP-931HL80/Desktop/Montana State University/Research/11-12-2023/Dataset/PE32_Dataset/')
               print("This is a 32-bit executable.")

           elif pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
               file.close()
               num_pe64 = num_pe64 + 1
               move_file(file_path,
                         r'C:/Users/defaultuser0.DESKTOP-931HL80/Desktop/Montana State University/Research/11-12-2023/Dataset/PE64_Dataset/')
               print("This is a 64-bit executable.")
   return num_pe32, num_pe64

def writeDatasetInfo(file_path, data_to_write):
    with open(file_path, 'a') as file:
        file.write(data_to_write)


def createDataset(data_dir, dataset_name=None, out_datainfo_path=None):
    if not os.path.exists(data_dir):
        print(f"Source directory '{data_dir}' does not exist.")
        return
    # Get a list of files in the data directory
    files = os.listdir(data_dir)
    num_pe32 = 0
    num_pe64 = 0
    for file_name in files:
        source_path = os.path.join(data_dir, file_name)
        num_pe32, num_pe64 = groupFile(source_path, num_pe32, num_pe64)
    #write dataset info to disk
    dataset_info = dataset_name + ' ' + 'num_pe32 ' + str(num_pe32) + ' '+'num_pe64 '+str(num_pe64)+'\n'

    writeDatasetInfo(out_datainfo_path, dataset_info)
    return True

def createDir(dir_name):
    # Create the destination directory if it doesn't exist
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)
        return True
    return False

"""
each public account can only process 500 files a day. Therefore, I divide a big dataset into smaller datasets with each being 500 files.
"""
def VirusTotalDataset(src_dataset_path, to_virusltoal_path=None, dataset_name=None, size_of_dataset=None):
    if not os.path.exists(src_dataset_path):
        print(f"Dataset directory '{src_dataset_path}' does not exist.")
        return
    files = os.listdir(src_dataset_path)
    file_index = 0
    out_data_path = ''
    for file_name in files:
            if (file_index % size_of_dataset) != 0:
                source_file_path = os.path.join(src_dataset_path, file_name)
                move_file(source_file_path, out_data_path)
                file_index = file_index + 1
            else:#create a new sub dir
                sub_dir = dataset_name + str(file_index)
                out_data_path = os.path.join(to_virusltoal_path, sub_dir)
                if not os.path.exists(out_data_path):
                    os.makedirs(out_data_path)
                source_file_path = os.path.join(src_dataset_path, file_name)
                move_file(source_file_path, out_data_path)
                file_index = file_index + 1



data_dir =r"C:/Users/defaultuser0.DESKTOP-931HL80/Downloads/VirusShare_00300/"
dataset_name = r'VirusShare_00300'
out_datainfo_path = r'C:/Users/defaultuser0.DESKTOP-931HL80/Desktop/Montana State University/Research/11-12-2023/dataset_information.txt'
#if(createDataset(data_dir=data_dir, dataset_name=dataset_name, out_datainfo_path=out_datainfo_path)):
#    print("dataset created")

src_dataset_path = r'C:/Users/defaultuser0.DESKTOP-931HL80/Desktop/Montana State University/Research/11-12-2023/Dataset/PE64_Dataset/'
to_virusltoal_path = r'C:/Users/defaultuser0.DESKTOP-931HL80/Desktop/Montana State University/Research/11-12-2023/VirusTotal64/'
dataset_name = r'virustotal'
size_of_dataset = 500
VirusTotalDataset(src_dataset_path, to_virusltoal_path=to_virusltoal_path, dataset_name=dataset_name, size_of_dataset=500)

