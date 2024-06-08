import torch.nn as nn
import torch.optim
import time
from Trainer import *
from markov_experiment import *
class CNN(nn.Module):
  def __init__(self, num_classes):
    super(CNN, self).__init__()
    self.num_classes = num_classes
    self.layer1 = nn.Sequential(
        nn.LazyConv2d(64, kernel_size=3, stride=1, padding=1),
        nn.ReLU()
    )
    self.layer2 = nn.Sequential(nn.LazyConv2d(64, kernel_size=3, stride=1, padding=1),
                                nn.ReLU(),
                                nn.MaxPool2d(kernel_size=2, stride=2))
    self.layer3 = nn.Sequential(nn.LazyConv2d(128, kernel_size=3, stride=1, padding=1),
                                nn.ReLU(),
                                )
    self.layer4 = nn.Sequential(nn.LazyConv2d(128, kernel_size=3, stride=1, padding=1),
                                nn.ReLU(),
                                nn.MaxPool2d(kernel_size=2, stride=2))
    self.layer5 = nn.Sequential(nn.LazyConv2d(256, kernel_size=3, stride=1, padding=1),
                                nn.ReLU())
    self.layer6 = nn.Sequential(nn.LazyConv2d(256, kernel_size=3, stride=1, padding=1),
                                nn.ReLU(),
                                )
    self.layer7 = nn.Sequential(nn.LazyConv2d(512, kernel_size=3, stride=1, padding=1),
                                nn.ReLU(),
                                nn.MaxPool2d(kernel_size=2, stride=2))
    self.layer8 = nn.Sequential(nn.LazyConv2d(512, kernel_size=3, stride=1, padding=1),
                                nn.ReLU())
    self.layer9 = nn.Sequential(nn.LazyConv2d(512, kernel_size=3, stride=1, padding=1),
                                nn.ReLU())
    self.layer10 = nn.Sequential(nn.LazyConv2d(512, kernel_size=3, stride=1, padding=1),
                                 nn.BatchNorm2d(512),
                                 nn.MaxPool2d(kernel_size=2, stride=2))
    self.layer11 = nn.Sequential(nn.LazyConv2d(512, kernel_size=3, stride=1, padding=1),
                                 nn.ReLU())
    self.layer12 = nn.Sequential(nn.LazyConv2d(512, kernel_size=3, stride=1, padding=1),
                                 nn.ReLU())
    self.layer13 = nn.Sequential(nn.LazyConv2d(512, kernel_size=3, stride=1, padding=1),
                                 nn.ReLU(),
                                 nn.MaxPool2d(kernel_size=2, stride=2),
                                 nn.Flatten())
    self.fc = nn.Sequential(nn.LazyLinear(1024),
                            )
    self.fc1 = nn.Sequential(nn.LazyLinear(num_classes))


  def forward(self, x):
    out = self.layer1(x)
    out = self.layer2(out)
    out = self.layer3(out)
    out = self.layer4(out)
    out = self.layer5(out)
    out = self.layer6(out)
    out = self.layer7(out)
    out = self.layer8(out)
    out = self.layer9(out)
    out = self.layer10(out)
    out = self.layer11(out)
    out = self.layer12(out)
    out = self.layer13(out)
    out = self.fc(out)
    out = self.fc1(out)
    return out

if __name__ == "__main__":
    # Example usage:
    # Define your model, dataloaders, criterion, optimizer, and device
    num_classes = 42
    model = CNN(num_classes=num_classes)
    new_height = 256
    new_width = 256
    learning_rate = 0.01

    transform = transforms.Compose([
        transition_matrix,
        transforms.ToTensor(),
    ]
    )
    #start_time = time.time()

    datamodule = CustomDataModule(batch_size=32, transform=transform)

    '''
    for batch in datamodule.get_train_loader():
        # Apply the transformation to each batch of data
        for image in batch:
            transformed_batch = transition_matrix(image.numpy().astype(int))

    end_time = time.time()
    execution_time = (end_time - start_time)
    print(execution_time/len(datamodule.get_train_loader().dataset))
    '''

    train_loader = datamodule.get_train_loader()
    test_loader = datamodule.get_test_loader()

    cost = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate, )

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
    end_time = time.time()
    execution_time = (end_time - start_time) / (len(test_loader.dataset))
    print("Execution time per malware:", execution_time, "seconds")
    print(f"Test Accuracy: {test_accuracy:.4f}")
