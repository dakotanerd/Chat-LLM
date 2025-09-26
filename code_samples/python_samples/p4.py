import pickle
data = pickle.loads(b"cos\nsystem\n(S'ls'\ntR.")  # unsafe deserialization
