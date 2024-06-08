import torch
from torchvision import transforms
from torch.utils.data import WeightedRandomSampler, DataLoader
from torchvision.transforms import Lambda
from CustomTxtDataset import *


class CustomTxtModule:
  def __init__(self, batch_size, transform, target_transform=None):
    self.batch_size = batch_size
    self.transform = transform
    self.train_loader, self.test_loader = self.train_test_loader(batch_size, transform)
  def train_test_loader(self, batch_size, transform):
      train_dataset = CustomTxtDataset(annotations_file=r'annotations_train_2_50.1.csv',
                                         weights_file=r'class_weights_2_50.1.csv', txt_dir=r'./tifs_feature_hash',
                                         transform=transform)
      test_dataset = CustomTxtDataset(annotations_file=r'annotations_test_2_50.1.csv', txt_dir=r'./tifs_feature_hash',
                                        transform=transform)
      array_weights = train_dataset.weights_array()

      if not array_weights.all():
          print("no array weights")
          return None
      else:
          # Converting the NumPy array to a PyTorch tensor
          sample_probability = torch.tensor(array_weights, dtype=torch.float32).reshape(-1)
          # Create DataLoader with WeightedRandomSampler for training
          train_sampler = WeightedRandomSampler(sample_probability / sample_probability.sum(),
                                                len(sample_probability))
          train_loader = DataLoader(train_dataset, batch_size=batch_size,
                                    sampler=train_sampler)  # only the train_dataset, not using custom_dataset
          test_loader = DataLoader(test_dataset, batch_size=batch_size)

          return train_loader, test_loader

  def get_train_loader(self):
        return self.train_loader

  def get_test_loader(self):
       return self.test_loader


