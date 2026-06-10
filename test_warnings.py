import warnings
import numpy as np

warnings.filterwarnings('error')

def test():
    T = np.random.rand(35, 35)
    row_sums = T.sum(axis=1, keepdims=True)
    T = T / row_sums
    belief = np.ones(35) / 35
    try:
        belief = belief @ T
    except Exception as e:
        print(f"Error: {e}")

test()
