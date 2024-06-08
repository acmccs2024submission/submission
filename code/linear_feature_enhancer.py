import cv2
import os


def clahe(img_dir, out_dir):
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
                        image = cv2.imread(source_filepath)
                        image = image.reshape(image[0], -1)
                        # Split the LAB image into channels
                        l_channel, a_channel, b_channel = cv2.split(image)

                        # Apply CLAHE to the L channel
                        clahe = cv2.createCLAHE(clipLimit=4.0, tileGridSize=(image[0], 1))
                        clahe_l = clahe.apply(l_channel)
                        clahe_a = clahe.apply(a_channel)
                        clahe_b = clahe.apply(b_channel)
                        # Merge the CLAHE enhanced L channel with the original A and B channels
                        clahe_lab_image = cv2.merge((clahe_l, clahe_a, clahe_b))
                        dest_filepath = os.path.join(destination_dir, filename)
                        # Convert the CLAHE enhanced LAB image back to RGB color space
                        cv2.imwrite(dest_filepath, clahe_lab_image)

    print("CLAHE enhanced image saved successfully.")


#clahe(r'malimg_feature_maps', r'clahecolor_malimg_finer_maps')
#clahe(r'tifs_grey_image',r'tifs_grey2clahe')

