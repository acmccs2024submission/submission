import torch
import torch.nn as nn
from Trainer import *
import time
class VGG_11(nn.Module):
    def __init__(self, arch, num_classes=42):
        super().__init__()
        conv_blks=[]
        for (num_convs, out_channels) in arch:
            conv_blks.append(self.vgg_block(num_convs, out_channels))
        self.net = nn.Sequential(*conv_blks, nn.Flatten(),
                                 nn.LazyLinear(4096), nn.ReLU(), nn.Dropout(0.5),
                                 nn.LazyLinear(4096), nn.ReLU(), nn.Dropout(0.5),
                                 nn.LazyLinear(num_classes))
        self.net.apply(self.init_cnn)

    def vgg_block(self, num_convs, out_channels):
        layers = []
        for _ in range(num_convs):
            layers.append(nn.LazyConv2d(out_channels=out_channels, kernel_size=3, padding=1))
            layers.append(nn.BatchNorm2d(out_channels))
            layers.append(nn.ReLU())
        layers.append(nn.MaxPool2d(kernel_size=2, stride=2))
        return nn.Sequential(*layers)

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
    model = VGG_11(arch=((1, 64), (1, 128), (2, 256), (2, 512), (2, 512)), num_classes=num_classes)

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
    trainer.train(num_epochs=100)
    start = time.time()
    # Evaluate the model on the test set
    test_accuracy = trainer.test()
    print(f"Test Accuracy: {test_accuracy:.4f}")
    end = time.time()
    execution_time = (end - start) / len(test_loader.dataset)
    print("Execution time per malware:", execution_time, "seconds")