import os
from PIL import Image
import torch
from Trainer import *
from img_gist_feature.utils_gist import *
from torchvision import transforms
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import confusion_matrix

if __name__ == "__main__":
    # Load data from CSV file
    train = pd.read_csv('train_tift_grey_similarity.csv')

    # Separate features and labels
    x_train = train.drop(columns=['label']).values  # Extract all columns except the 'label' column as features
    y_train = train['label'].values  # Extract the 'label' column as labels
    print(x_train.shape)
    print(y_train[:10])

    test = pd.read_csv('test_tift_grey_similarity.csv')

    #Separate features and labels
    x_test = test.drop(columns=['label']).values
    y_test = test['label'].values
    start_time = time.time()
    # Create and fit the KNN classifier
    clf = KNeighborsClassifier(1, weights='distance')
    # Training
    clf.fit(x_train, y_train)
    # Predict labels for test data
    y_predict = clf.predict(x_test)
    end_time = time.time()
    execution_time = (end_time - start_time)/len(y_test)
    print("Execution time per malware:", execution_time, "seconds")

    # Calculate accuracy
    accuracy = accuracy_score(y_test, y_predict)
    precision = precision_score(y_test, y_predict, average='weighted', zero_division=0)
    recall = recall_score(y_test, y_predict, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_predict, average='weighted', zero_division=0)
    #print(accuracy)
    print("precison", precision)
    print("recall",recall)
    print("f1", f1)
    print(accuracy)
    conf_matrix = confusion_matrix(y_test, y_predict)
    # Calculate true positives (TP) for each class
    TP = conf_matrix.diagonal()

    # Calculate the total number of instances for each class
    total_instances_per_class = conf_matrix.sum(axis=1)

    # Calculate accuracy for each class
    class_accuracy = TP / total_instances_per_class
    print(class_accuracy)


