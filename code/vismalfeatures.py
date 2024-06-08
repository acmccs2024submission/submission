import cv2
import os
import time

def clahe(img_dir, out_dir):
    execution_time=0
    if not os.path.exists(img_dir):
        os.makedirs(img_dir)

    for root, dirs, files in os.walk(img_dir):
        for subdirectory in dirs:
            subdirectory_path = os.path.join(root, subdirectory)
            destination_dir = os.path.join(out_dir, subdirectory)
            if not os.path.exists(destination_dir):
                os.makedirs(destination_dir)
            # Check if the subdirectory is not empty
            if os.listdir(subdirectory_path):
                # Iterate through files in the subdirectory
                for filename in os.listdir(subdirectory_path):
                    source_filepath = os.path.join(subdirectory_path, filename)
                    if os.path.exists(source_filepath):
                        # Create a CLAHE object with a specified tile grid size (e.g., 8x8)
                        start_time = time.time()
                        image = cv2.imread(source_filepath, 0)
                        clahe = cv2.createCLAHE(clipLimit=4.0, tileGridSize=(2, 23))
                        if image.shape[0] == 64:
                            clahe = cv2.createCLAHE(clipLimit=4.0, tileGridSize=(2, 23))
                        if image.shape[0] == 128:
                            clahe = cv2.createCLAHE(clipLimit=4.0, tileGridSize=(4, 23))
                        if image.shape[0] == 256:
                            clahe = cv2.createCLAHE(clipLimit=4.0, tileGridSize=(8, 23))
                        if image.shape[0] == 384:
                            clahe = cv2.createCLAHE(clipLimit=4.0, tileGridSize=(12, 23))
                        if image.shape[0] == 512:
                            clahe = cv2.createCLAHE(clipLimit=4.0, tileGridSize=(16, 23))
                        if image.shape[0] == 768:
                            clahe = cv2.createCLAHE(clipLimit=4.0, tileGridSize=(24, 23))
                        if image.shape[0] == 1024:
                            clahe = cv2.createCLAHE(clipLimit=4.0, tileGridSize=(32, 23))
                        clahe_image = clahe.apply(image)
                        end_time = time.time()
                        per_execution = (end_time - start_time)
                        execution_time+=per_execution
                        dest_filepath = os.path.join(destination_dir, filename)
                        cv2.imwrite(dest_filepath, clahe_image)
    execution_time = execution_time/9339
    print("Execution time per malware:", execution_time, "seconds")


    print("CLAHE enhanced image saved successfully.")


clahe(r'tifs_grey_image', r'tifs_vismal')