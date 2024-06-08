from Trainer import *
from img_gist_feature.utils_gist import *
from torchvision import transforms


def getGistFeature(images):
    gist_helper = GistUtils()
    gist_feature_set = []
    labels = []
    for image, label in images:
        image =image.squeeze().numpy()
        #image = image.squeeze().permute(1, 2, 0).numpy()
        #print(image.shape, label.shape)
        #image = cv2.cvtColor(image, cv2.COLOR_RGB2BGR)
        image = cv2.cvtColor(image, cv2.COLOR_GRAY2BGR)
        # print(image.shape, label.shape)
        np_gist = gist_helper.get_gist_vec(image, mode="gray").flatten()
        gist_feature_set.append(np_gist)
        labels.append(label.item())
    return gist_feature_set, labels


def output_features():
    transform = transforms.Compose([
        # transforms.Resize((new_height, new_width)),
        transforms.ToTensor()
    ]
    )

    # Assuming you have train_dataloader and test_dataloader
    datamodule = CustomDataModule(batch_size=1, transform=transform)
    train_loader = datamodule.get_train_loader()
    test_loader = datamodule.get_test_loader()
    start_time = time.time()
    train_gist_feature_set, train_labels = getGistFeature(train_loader)
    end_time = time.time()
    execution_time = (end_time - start_time)/len(train_loader.dataset)
    print("Execution time per malware:", execution_time, "seconds")
    print(np.array(train_gist_feature_set).shape)
    print(np.array(train_labels).shape)

    # Specify the path to the CSV file
    csv_file = 'train_tift_grey_similarity.csv'
    feature_names = [f'feature{i + 1}' for i in range(np.array(train_gist_feature_set).shape[1])]

    # Specify the title line
    title_line = feature_names + ['label']

    # Write the features to the CSV file
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(title_line)
        for feature, label in zip(train_gist_feature_set, train_labels):
            writer.writerow(np.concatenate((feature, [label]), axis=None))

    test_gist_set, test_labels = getGistFeature(test_loader)
    # Specify the path to the CSV file
    csv_file = 'test_tift_grey_similarity.csv'

    # Write the features to the CSV file
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(title_line)

        for feature, label in zip(test_gist_set, test_labels):
            writer.writerow(np.concatenate((feature, [label]), axis=None))

output_features()