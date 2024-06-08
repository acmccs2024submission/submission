import torch.nn as nn
import torch.optim

from Trainer import *
from markov_experiment import *
import time
class CNN(nn.Module):
  def __init__(self, num_classes):
    super(CNN, self).__init__()
    self.num_classes = num_classes
    self.layer1 = nn.Sequential(
        nn.LazyConv2d(64, kernel_size=5, stride=1, padding=2),
        nn.MaxPool2d(kernel_size=2, stride=1, padding=(0, 1))
    )
    self.layer2 = nn.Sequential(nn.LazyConv2d(128, kernel_size=5, stride=1, padding=2),
                                nn.MaxPool2d(kernel_size=2, stride=1, padding=(0, 1)))
    self.layer3 = nn.Sequential(nn.LazyConv2d(256, kernel_size=2, stride=1, padding=(0, 1)),
                                nn.MaxPool2d(kernel_size=2, stride=1, padding=(0, 1)))
    self.layer4 = nn.Sequential(nn.LazyConv2d(256, kernel_size=2, stride=1, padding=(0, 1)),
                                nn.MaxPool2d(kernel_size=2, stride=1, padding=(0, 1)))
    self.layer5 = nn.Sequential(nn.Dropout(0.5),
                                nn.Flatten())
    self.layer6 = nn.Sequential(nn.LazyLinear(256),)
    self.layer7 = nn.Sequential(nn.LazyLinear(128))
    self.fc = nn.Sequential(nn.LazyLinear(num_classes))


  def forward(self, x):
    out = self.layer1(x)
    out = self.layer2(out)
    out = self.layer3(out)
    out = self.layer4(out)
    out = self.layer5(out)
    out = self.layer6(out)
    out = self.layer7(out)
    out = self.fc(out)
    return out


if __name__ == "__main__":
      # Example usage:
      # Define your model, dataloaders, criterion, optimizer, and device
      num_classes = 42
      model = CNN(num_classes=num_classes)
      new_height = 64
      new_width = 64
      learning_rate = 0.01
      transform = transforms.Compose([
          transforms.Resize((new_height, new_width)),
          transforms.ToTensor(),
      ]
      )

      datamodule = CustomDataModule(batch_size=32, transform=transform)
      train_loader = datamodule.get_train_loader()
      test_loader = datamodule.get_test_loader()

      cost = nn.CrossEntropyLoss()
      optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate, weight_decay=0.01)

      device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
      model = model.to(device)
      # ...
      # Instantiate the Trainer class
      trainer = Trainer(model, train_loader, test_loader, cost, optimizer, device)
      # Train the model for a specified number of epochs
      trainer.train(num_epochs=10)

      start_time = time.time()
      # Evaluate the model on the test set
      test_accuracy = trainer.test()
      end_time = time.time()
      execution_time = (end_time - start_time) / (len(test_loader.dataset))
      print("Execution time per malware:", execution_time, "seconds")

      print(f"Test Accuracy: {test_accuracy:.4f}")