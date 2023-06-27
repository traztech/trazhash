import hashlib
import platform
import socket

__version__ = '0.1.0'

class FileReadError(Exception):
    """
    Exception raised when there is an error reading a file.
    """
    pass


def gather_system_values():
    """
    Gathers system values such as system name, node name, release, version,
    machine, processor, host name, name info, and FQDN.

    Returns:
        list: A list of system values.
    """
    system_info = platform.uname()
    system_values = [
        system_info.system,
        system_info.node,
        system_info.release,
        system_info.version,
        system_info.machine,
        platform.processor(),
        socket.gethostname(),
        socket.getfqdn(),
        socket.getnameinfo()
    ]
    return system_values


def hash_string(data, inner_hash_algo='sha512', outer_hash_algo='sha256'):
    """
    Hashes the input string with the system's values using the specified hash algorithms.

    Parameters:
        data (str): The input string to hash.
        inner_hash_algo (str): The hashing algorithm for the inner hash. Defaults to 'sha512'.
        outer_hash_algo (str): The hashing algorithm for the outer hash. Defaults to 'sha256'.

    Returns:
        str: The resulting hash.
    """
    system_values = gather_system_values()
    combined_data = ''.join(system_values) + data
    inner_hash = hashlib.new(inner_hash_algo, combined_data.encode()).hexdigest()
    final_hash = hashlib.new(outer_hash_algo, inner_hash.encode()).hexdigest()
    return final_hash


def hash_file(file_path, inner_hash_algo='sha512', outer_hash_algo='sha256'):
    """
    Hashes the content of a file with the system's values using the specified hash algorithms.

    Parameters:
        file_path (str): The path to the file to hash.
        inner_hash_algo (str): The hashing algorithm for the inner hash. Defaults to 'sha512'.
        outer_hash_algo (str): The hashing algorithm for the outer hash. Defaults to 'sha256'.

    Returns:
        str: The resulting hash.

    Raises:
        FileReadError: If the file cannot be read.
    """
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
            return hash_string(file_data, inner_hash_algo, outer_hash_algo)
    except IOError:
        raise FileReadError("Error: Unable to read the file.")

def verify(plain_text, hash_to_verify, inner_hash_algo='sha512', outer_hash_algo='sha256'):
    """
    Verifies if the hash of the input text with system values is equal to the given hash.

    Parameters:
        plain_text (str): The input text to verify.
        hash_to_verify (str): The hash to verify against.
        inner_hash_algo (str): The hashing algorithm for the inner hash. Defaults to 'sha512'.
        outer_hash_algo (str): The hashing algorithm for the outer hash. Defaults to 'sha256'.

    Returns:
        bool: True if the hashes match, False otherwise.
    """
    computed_hash = hash_string(plain_text, inner_hash_algo, outer_hash_algo)
    return computed_hash == hash_to_verify


# Example usage
print(hash_string("hello"))