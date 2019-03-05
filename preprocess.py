from pycparser import preprocess_file
import re

def preprocess(file, cpp_args=''):       
    preprocessed = preprocess_file(file, cpp_args=cpp_args)
    preprocessed = re.sub(r'#.*\n', '', preprocessed)
    return preprocessed