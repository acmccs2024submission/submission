import torch.nn as nn
import torch
import torch.nn as nn
import torch.optim as optim
from torchvision import transforms
from Trainer import *
import time
class DNN(nn.Module):
  def __init__(self, num_classes):
    super(DNN, self).__init__()
    self.num_classes = num_classes
    self.flatten =nn.Flatten()
    self.fc1 = nn.LazyLinear(4096)
    self.fc2 = nn.LazyLinear(4096)
    self.fc3 = nn.Sequential(nn.LazyLinear(num_classes))


  def forward(self, x):
    x = self.flatten(x)
    out = self.fc1(x)
    out = self.fc2(out)
    out = self.fc3(out)
    return out

if __name__ == "__main__":
    # Example usage:
    # Define your model, dataloaders, criterion, optimizer, and device
    num_classes = 25
    model = DNN(num_classes=num_classes)
    new_height = 128
    new_width = 512
    learning_rate = 0.01
    transforms = transforms.Compose([
        transforms.Resize((new_height, new_width)),
        transforms.ToTensor()
    ]
    )

    datamodule = CustomDataModule(batch_size=32, transform=transforms)
    train_loader = datamodule.get_train_loader()
    test_loader = datamodule.get_test_loader()
    print(len(test_loader))

    cost = nn.CrossEntropyLoss()
    optimizer = torch.optim.SGD(model.parameters(), lr=learning_rate, )

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = model.to(device)
    # ...
    # Instantiate the Trainer class
    trainer = Trainer(model, train_loader, test_loader, cost, optimizer, device)
    # Train the model for a specified number of epochs
    trainer.train(num_epochs=1)
    start_time = time.time()
    # Evaluate the model on the test set
    test_accuracy = trainer.test()
    print(f"Test Accuracy: {test_accuracy:.4f}")
    end_time = time.time()
    execution_time = (end_time - start_time) / (len(test_loader.dataset))
    print("Execution time per malware:", execution_time, "seconds")