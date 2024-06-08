import torch
from torchvision import transforms
from torch.utils.data import WeightedRandomSampler, DataLoader
from torchvision.transforms import Lambda
from CustomImageDataset import *


class CustomDataModule:
  def __init__(self, batch_size, transform, target_transform=None):
    self.batch_size = batch_size
    self.transform = transform
    self.train_loader, self.test_loader = self.train_test_loader(batch_size, transform)
  def train_test_loader(self, batch_size, transform):
      train_dataset = CustomImageDataset(annotations_file=r'malimg_train_2_240.1.csv',
                                         weights_file=r'malimg_class_2_240.1.csv', img_dir=r'./clahecolor_malimg_finer_maps',
                                         transform=transform)
      test_dataset = CustomImageDataset(annotations_file=r'malimg__test_2_240.1.csv', img_dir=r'./clahecolor_malimg_finer_maps',
                                        transform=transform)
      array_weights = train_dataset.weights_array()

      if not array_weights.all():
          print("no array weights")
          return None
      else:
          # Converting the NumPy array to a PyTorch tensor
          sample_probability = torch.tensor(array_weights, dtype=torch.float32).reshape(-1)
          print(sample_probability[:10])
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


"""
new_height = 512
new_width = 472
batch_size = 32
transforms = transforms.Compose([
        transforms.Resize((new_height, new_width)),
        transforms.ToTensor()])
p1 = CustomDataModule(batch_size, transforms)

print(p1.get_train_loader())
print(p1.get_test_loader())

"""
