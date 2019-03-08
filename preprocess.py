from pycparser import preprocess_file
import re

def preprocess(file: str, cpp_args: str='') -> str:
    cpp_args = '-P ' + cpp_args
    preprocessed = preprocess_file(file, cpp_args=cpp_args)
    return preprocessed
