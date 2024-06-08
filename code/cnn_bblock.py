import torch
import torch.nn as nn
from Trainer import *
import time
class cnn_bblock(nn.Module):
    def __init__(self, num_classes=42):
        super().__init__()

        self.net = nn.Sequential(nn.LazyConv2d(out_channels=32, kernel_size=2),
                                 nn.LazyConv2d(out_channels=32, kernel_size=3), nn.MaxPool2d(kernel_size=2, stride=2),nn.Dropout(0.5),
                                 nn.LazyConv2d(out_channels=32, kernel_size=4), nn.MaxPool2d(kernel_size=2, stride=2), nn.Dropout(0.5),
                                 nn.Flatten(), nn.LazyLinear(512), nn.Tanh(), nn.LazyLinear(256),nn.Tanh(),
                                 nn.LazyLinear(num_classes), nn.Softmax())
        self.net.apply(self.init_cnn)



    def init_cnn(self, module):
        """Initialize weights for CNNs.

        Defined in :numref:`sec_lenet`"""
        if type(module) == nn.Linear or type(module) == nn.Conv2d:
            nn.init.xavier_uniform_(module.weight)

    def layer_summary(self, X_shape):
        """Defined in :numref:`sec_lenet`"""
        X = torch.randn(*X_shape)
        for layer in self.net:
            X = layer(X)
            print(layer.__class__.__name__, 'output shape:\t', X.shape)
    def forward(self, X):
        """Defined in :numref:`sec_linear_concise`"""
        return self.net(X)


if __name__ == "__main__":
    # Example usage:
    # Define your model, dataloaders, criterion, optimizer, and device
    num_classes = 42
    model = cnn_bblock(num_classes=num_classes)

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
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate, )

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = model.to(device)
    # ...
    # Instantiate the Trainer class
    trainer = Trainer(model, train_loader, test_loader, cost, optimizer, device)
    # Train the model for a specified number of epochs
    trainer.train(num_epochs=100)

    start_time = time.time()
    # Evaluate the model on the test set
    test_accuracy = trainer.test()
    print(f"Test Accuracy: {test_accuracy:.4f}")
    end_time = time.time()
    execution_time = (end_time - start_time) / (len(test_loader.dataset))
    print("Execution time per malware:", execution_time, "seconds")

