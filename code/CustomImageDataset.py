import os
import pandas as pd
from torch.utils.data import Dataset
from PIL import Image


class CustomImageDataset(Dataset):
    def __init__(self, annotations_file,  img_dir, weights_file=None, transform=None, target_transform=None):
        # Reading CSV file into a pandas DataFrame
        self.weights_file = weights_file
        self.img_labels = pd.read_csv(annotations_file)
        self.img_dir = img_dir
        self.transform = transform
        self.target_transform = target_transform

    def __len__(self):
        return len(self.img_labels)

    def __getitem__(self, idx):
        img_path = self.img_dir + '/'+ self.img_labels.iloc[idx, 0]
        #print(img_path)
        image = Image.open(img_path)
        label = self.img_labels.iloc[idx, 1]
        #print(label)
        if self.transform:
            image = self.transform(image)
        if self.target_transform:
            label = self.target_transform(label)
        return image, label

    def weights_array(self):
        if self.weights_file:
            return pd.read_csv(self.weights_file).values
        return None


