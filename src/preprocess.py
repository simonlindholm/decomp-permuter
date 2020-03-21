from typing import List
from pycparser import preprocess_file
import re


def preprocess(file: str, cpp_args: List[str] = []) -> str:
    preprocessed = preprocess_file(file, cpp_args=cpp_args + ["-P", "-nostdinc"])
    return preprocessed
