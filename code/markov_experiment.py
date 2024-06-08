import numpy as np
import torch
import time


def transition_matrix(image, n=1):
    '''
    Computes the transition matrix from Markov chain sequence of order `n`.

    :param arr: Discrete Markov chain state sequence in discrete time with states in 0, ..., N
    :param n: Transition order
    '''

    image = np.squeeze(np.array(image))
    M = np.zeros(shape=(256, 256))
    for (i, j) in zip(image, image[1:]):
        M[i, j] += 1
    #print(M.sum())
    M_sum = np.ma.masked_equal(M.sum(axis=1), 0)
    T = (M.T / M_sum).T

    #print("Execution time per malware:", execution_time, "seconds")
    return np.linalg.matrix_power(T, n).astype(np.float32)


def doubletofloat64(image):
    return image.to(torch.float32)