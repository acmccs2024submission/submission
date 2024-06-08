
from CustomDataModule import *
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
import csv
import numpy as np
from sklearn.metrics import confusion_matrix
class Trainer:
    def __init__(self, model, train_loader, test_loader, criterion, optimizer, device=None):
        self.model = model
        self.train_loader = train_loader
        self.test_loader = test_loader
        self.criterion = criterion
        self.optimizer = optimizer
        self.device = device

    def train_epoch(self):
        self.model.train()
        total_loss = 0.0
        correct_predictions = 0
        total_samples = 0
        steps = 0
        for inputs, labels in self.train_loader:
            inputs = inputs.float()
            if self.device:
                inputs, labels = inputs.to(self.device), labels.to(self.device)

            self.optimizer.zero_grad()
            outputs = self.model(inputs)
            loss = self.criterion(outputs, labels)
            loss.backward()
            self.optimizer.step()

            total_loss += loss.item()
            _, predicted = torch.max(outputs, 1)
            correct_predictions += (predicted == labels).sum().item()
            total_samples += labels.size(0)
            steps = steps+1
            print(f"steps {steps}/{len(self.train_loader)} -> "
                  f"Train Loss: {total_loss/total_samples:.4f}, Train Accuracy: {correct_predictions / total_samples:.4f}  ")
        return total_loss / total_samples, correct_predictions / total_samples

    def test(self):
        self.model.eval()
        correct_predictions = 0
        total_samples = 0
        # Initialize lists to store predictions and ground truth labels
        all_predictions = []
        all_labels = []

        with torch.no_grad():
            for inputs, labels in self.test_loader:
                #print("shape", inputs.shape)
                inputs = inputs.float()
                if self.device:
                   inputs, labels = inputs.to(self.device), labels.to(self.device)

                outputs = self.model(inputs)
                #print(outputs[0])
                _, predicted = torch.max(outputs, 1)
                correct_predictions += (predicted == labels).sum().item()
                total_samples += labels.size(0)
                all_predictions.extend(torch.argmax(outputs, axis=1).cpu().numpy())
                all_labels.extend(labels.cpu().numpy())

            # Convert lists to numpy arrays
            all_predictions = np.array(all_predictions)
            all_labels = np.array(all_labels)
            # Compute metrics for each class
            accuracy = accuracy_score(all_labels, all_predictions)
            precision = precision_score(all_labels, all_predictions, average=None, zero_division=0)
            recall = recall_score(all_labels, all_predictions, average=None, zero_division=0)
            f1 = f1_score(all_labels, all_predictions, average='weighted', zero_division=0)

            #classes = sorted(set(all_labels))
            #conf_matrix = confusion_matrix(all_labels, all_predictions, labels=classes)
            # Print results for each class
            #for i, cls in enumerate(classes):
            #    print(f"Class: {cls}")
            #    print(f"Precision: {precision[i]}")
            #    print(f"Recall: {recall[i]}")
            #    print(f"F1 Score: {f1[i]}")
           #     print(f"Confusion Matrix: {conf_matrix[i]}")
            #    print()

            print(accuracy)
            print("precision",precision)
            print("recall",recall)
            print("f1", f1)

            # Path to the CSV file
            #csv_file_path = "tifs_grey_image.csv"

            # Open the CSV file in append mode ('a')
            #with open(csv_file_path, mode='a', newline='') as file:
            #    writer = csv.writer(file)

                # Write the list as a row in the CSV file
            #    writer.writerow([precision, recall, f1, accuracy])

            # Define the file name for the CSV
            csv_filename = "metrics_per_class.csv"
            conf_matrix = confusion_matrix(all_labels, all_predictions)
            # Calculate true positives (TP) for each class
            TP = conf_matrix.diagonal()

            # Calculate the total number of instances for each class
            total_instances_per_class = conf_matrix.sum(axis=1)

            # Calculate accuracy for each class
            class_accuracy = TP / total_instances_per_class
            print(class_accuracy)
            #print(conf_matrix)
            output_file_path =r'conf_matrix_ase_dataset.csv'
            # Write the data to the CSV file
            '''
            with open(output_file_path, 'w', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerows(conf_matrix)
            '''
        return correct_predictions / total_samples

    def train(self, num_epochs):
        for epoch in range(num_epochs):
            train_loss, train_accuracy = self.train_epoch()

            print(f"Epoch {epoch + 1}/{num_epochs} -> "
                  f"Train Loss: {train_loss:.4f}, Train Accuracy: {train_accuracy:.4f}  ")
            if epoch > 10:
                modelname =("./clahecolor_malimg_finer_maps_models/")+"img_malfiner_" + str(epoch) + ".pth"
                torch.save(self.model.state_dict(), modelname)
        print("Training completed.")


