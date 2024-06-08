import os
import pandas as pd
from torch.utils.data import Dataset
from PIL import Image


class CustomTxtDataset(Dataset):
    def __init__(self, annotations_file,  txt_dir, weights_file=None, transform=None, target_transform=None):
        # Reading CSV file into a pandas DataFrame
        self.weights_file = weights_file
        self.txt_labels = pd.read_csv(annotations_file)
        self.txt_dir = txt_dir
        self.transform = transform
        self.target_transform = target_transform

    def __len__(self):
        return len(self.txt_labels)

    def __getitem__(self, idx):
        txt_path = self.txt_dir + '/'+ self.txt_labels.iloc[idx, 0].split('.')[0]+'.txt'
        #print("txt_path",txt_path)
        try:
            with open(txt_path, 'r') as f:
                content = f.read()
                content = list(map(int, content.split(',')))
                # Do something with the content
                #print(f"Content of {txt_path}:\n{content[:100]}")  # Print first 100 characters
        except Exception as e:
            print(f"Failed to read {txt_path}: {e}")
        #print(img_path)
        label = self.txt_labels.iloc[idx, 1]
        #print(label)
        if self.transform:
            image = self.transform(content)
        if self.target_transform:
            label = self.target_transform(label)
        return image, label

    def weights_array(self):
        if self.weights_file:
            return pd.read_csv(self.weights_file).values
        return None


