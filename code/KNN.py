from CustomImageDataset import *
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
import numpy as np
import time
from sklearn.neighbors import KNeighborsClassifier

if __name__ == "__main__":
    train_dataset = CustomImageDataset(annotations_file=r'annotations_train_2_50.1.csv',
                                       weights_file=r'class_weights_2_50.1.csv', img_dir=r'tifs_grey_image',
                                       transform=None)
    test_dataset = CustomImageDataset(annotations_file=r'annotations_test_2_50.1.csv', img_dir=r'tifs_grey_image',
                                      transform=None)
    x_train = []
    y_train =[]
    start_time = time.time()
    for image, label in train_dataset:
        image = np.array(image.resize((512, 128))).flatten()
        x_train.append(image)
        y_train.append(label.item())
    end_time = time.time()
    execution_time = (end_time - start_time)/len(train_dataset)
    print("Execution time per malware:", execution_time, "seconds")
    x_test=[]
    y_test=[]
    for image, label in test_dataset:
        image = np.array(image.resize((512, 128))).flatten()
        x_test.append(image)
        y_test.append(label.item())

    # Create and fit the KNN classifier
    clf = KNeighborsClassifier(1, weights='distance')

    # Training
    clf.fit(x_train, y_train)

    # Predict labels for test data
    start_time = time.time()
    y_predict = clf.predict(x_test)
    end_time = time.time()
    execution_time = (end_time - start_time) / (len(test_dataset))
    print("Execution time per malware:", execution_time, "seconds")
    # Calculate accuracy
    accuracy = accuracy_score(y_test, y_predict)
    precision = precision_score(y_test, y_predict, average='weighted', zero_division=0)
    recall = recall_score(y_test, y_predict, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_predict, average='weighted', zero_division=0)
    print(accuracy)
    print(precision)
    print(recall)
    print(f1)
