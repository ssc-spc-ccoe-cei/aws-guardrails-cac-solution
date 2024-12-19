import zlib
import base64
import sys

def compress_file(filename) -> bytes:
    """Compresses the specified file using zlib.

    Args:
        filename (str): The path to the file to compress.

    Returns:
        bytes: The compressed data.
    """

    with open(filename, 'r') as f:
        data = f.read().replace('\n', '')

    compressed_data = zlib.compress(data.encode('utf-8'))
    return compressed_data

def base64_encode(b: bytes) -> bytes:
  """Encodes bytes using Base64 encoding.

  Args:
    b: The bytes to encode.

  Returns:
    The Base64-encoded bytes.
  """

  encoded_bytes = base64.b64encode(b)
  return encoded_bytes

if __name__ == "__main__":
  if len(sys.argv) > 1:
    filename = sys.argv[1]
    compressed_data = compress_file(filename)
    encoded_data = base64_encode(compressed_data)
    print(encoded_data)
  else:
    print("Please provide a filename as an argument.")