# import json
# import sys
#
# class JSONFileException(Exception):
#     pass
#
# class Enigma:
#     def __init__(self, hash_map, wheels, reflector_map):
#         self._hash_map = hash_map
#         self._inv_hash_map = {v: k for k, v in hash_map.items()}
#         self._wheels = wheels[:]
#         self._reflector_map = reflector_map
#         self._initial_wheels = wheels[:]
#
#
#     def calculate_wheels(self):
#         return (((2 * self._wheels[0]) - self._wheels[1] + self._wheels[2]) % 26)
#
#     def update_wheels(self, num_of_encryptions):
#         if self._wheels[0] + 1 > 8:
#             self._wheels[0] = 1
#         else:
#             self._wheels[0] += 1
#
#         if num_of_encryptions % 2 == 0:
#             self._wheels[1] *= 2
#         else:
#             self._wheels[1] -= 1
#
#         if num_of_encryptions % 10 == 0:
#             self._wheels[2] = 10
#         elif num_of_encryptions % 3 == 0:
#             self._wheels[2] = 5
#         else:
#             self._wheels[2] = 0
#
#     def encrypt(self, message):
#         encrypted_message = ""
#         num_of_encryptions = 0
#         for letter in message:
#             if not letter.islower():
#                 encrypted_message += letter
#                 self.update_wheels(num_of_encryptions)
#                 continue
#
#             i = self._hash_map[letter] #1
#
#             value = self.calculate_wheels() #2
#             if (value != 0):
#                 i += value
#             else:
#                 i += 1
#
#             i = i % 26 #3
#             c1 = self._inv_hash_map[i] #4
#             c2 = self._reflector_map[c1] #5
#             i = self._hash_map[c2] #6
#
#             if (value != 0): #7
#                 i -= value
#             else:
#                 i -= 1
#
#             i = i % 26 #8
#             c3 = self._inv_hash_map[i] #9
#
#             num_of_encryptions += 1
#             encrypted_message += c3
#             self.update_wheels(num_of_encryptions)
#
#         self._wheels = self._initial_wheels[:]
#         return encrypted_message
#
# def load_enigma_from_path(path):
#     try:
#         with open(path, 'r') as f:
#             loaded_dict = json.load(f)
#         return Enigma(loaded_dict["hash_map"], loaded_dict["wheels"], loaded_dict["reflector_map"])
#     except (Exception) as e:
#         raise JSONFileException()
#
# def encrypt_from_file(enigma, input_path):
#     messages = []
#     with open(input_path, 'r') as f:
#         for line in f:
#             line = line.strip()
#             if not line:
#                 continue
#             encrypted = enigma.encrypt(line)
#             messages.append(encrypted)
#     return messages
#
# def print_usage_error():
#     sys.stderr.write("Usage: python3 enigma.py -c <config_file> -i <input_file> -o <output_file>\n")
#     sys.exit(1)
#
# def print_runtime_error():
#     sys.stderr.write("The enigma script has encountered an error\n")
#     sys.exit(1)
#
# def main():
#     if '-c' not in sys.argv or '-i' not in sys.argv:
#         print_usage_error()
#
#     config_file = None
#     input_file = None
#     output_file = None
#     valid_flags = ['-c', '-i', '-o']
#
#     try:
#         for i in range(1, len(sys.argv), 2):
#             if i + 1 >= len(sys.argv):
#                 print_usage_error()
#
#             flag, value = sys.argv[i], sys.argv[i + 1]
#
#             if flag not in valid_flags:
#                 print_usage_error()
#             elif flag == '-c':
#                 config_file = value
#             elif flag == '-i':
#                 input_file = value
#             elif flag == '-o':
#                 output_file = value
#
#         if config_file is None or input_file is None:
#             print_usage_error()
#
#         enigma = load_enigma_from_path(config_file)
#         encrypted_messages = encrypt_from_file(enigma, input_file)
#
#         if output_file:
#             with open(output_file, 'w') as f:
#                 for message in encrypted_messages:
#                     f.write(message + '\n')
#         else:
#             for message in encrypted_messages:
#                 print(message)
#
#     except Exception:
#         print_runtime_error()
#
# if __name__ == '__main__':
#     main()

import json
import sys

class JSONFileException(Exception):
    pass

class Enigma:
    def __init__(self, hash_map, wheels, reflector_map):
        # Original maps and pre-computed inverse map
        self._hash_map       = hash_map
        self._inv_hash_map   = {v: k for k, v in hash_map.items()}
        # Wheels state
        self._wheels         = wheels[:]          # will mutate
        self._initial_wheels = wheels[:]          # backup
        self._reflector_map  = reflector_map

    def calculate_wheels(self):
        return (2*self._wheels[0] - self._wheels[1] + self._wheels[2]) % 26

    def update_wheels(self, num_encrypted):
        # W1 always steps by +1, wrapping at 8→1
        self._wheels[0] = (self._wheels[0] % 8) + 1

        # W2: based on count of *real* encrypted so far
        if num_encrypted % 2 == 0:
            self._wheels[1] *= 2
        else:
            self._wheels[1] -= 1

        # W3: based on same count
        if num_encrypted % 10 == 0:
            self._wheels[2] = 10
        elif num_encrypted % 3 == 0:
            self._wheels[2] = 5
        else:
            self._wheels[2] = 0

    def encrypt(self, message):
        result          = ""
        num_encrypted   = 0

        for ch in message:
            # 1) Pass through non-lowercase, still step wheels
            if not ch.islower():
                result += ch
                self.update_wheels(num_encrypted)
                continue

            # 2) Map letter→number
            i = self._hash_map[ch]

            # 3) Forward through wheels
            offset = self.calculate_wheels()
            i += offset or 1
            i %= 26

            # 4) Reflect
            c1 = self._inv_hash_map[i]
            c2 = self._reflector_map[c1]
            i  = self._hash_map[c2]

            # 5) Backward through wheels
            i -= offset or 1
            i %= 26

            # 6) Map back to char
            c3 = self._inv_hash_map[i]
            result += c3

            # 7) Advance wheel state
            num_encrypted += 1
            self.update_wheels(num_encrypted)

        # Restore to initial position
        self._wheels = self._initial_wheels[:]
        return result

def load_enigma_from_path(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        # validate keys
        for key in ("hash_map", "wheels", "reflector_map"):
            if key not in cfg:
                raise JSONFileException()
        return Enigma(cfg["hash_map"], cfg["wheels"], cfg["reflector_map"])
    except (OSError, json.JSONDecodeError, JSONFileException):
        raise JSONFileException()

def encrypt_from_file(enigma, input_path):
    messages = []
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    continue
                messages.append(enigma.encrypt(line))
    except OSError:
        # file-read error
        raise
    return messages

def print_usage_error():
    sys.stderr.write(
        "Usage: python3 enigma.py -c <config_file> -i <input_file> -o <output_file>\n"
    )
    sys.exit(1)

def print_runtime_error():
    sys.stderr.write("The enigma script has encountered an error\n")
    sys.exit(1)

def main():
    if '-c' not in sys.argv or '-i' not in sys.argv:
        print_usage_error()

    config_file = input_file = output_file = None
    valid_flags = ['-c', '-i', '-o']

    # parse flags
    for i in range(1, len(sys.argv), 2):
        if i+1 >= len(sys.argv):
            print_usage_error()
        flag, val = sys.argv[i], sys.argv[i+1]
        if flag not in valid_flags:
            print_usage_error()
        if flag == '-c':
            config_file = val
        elif flag == '-i':
            input_file = val
        else:
            output_file = val

    if not config_file or not input_file:
        print_usage_error()

    try:
        enigma = load_enigma_from_path(config_file)
        encrypted_messages = encrypt_from_file(enigma, input_file)
    except JSONFileException:
        print_runtime_error()
    except:
        # any other runtime error (e.g., can't open input_file)
        print_runtime_error()

    # output
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for msg in encrypted_messages:
                    f.write(msg + "\n")
        except:
            print_runtime_error()
    else:
        for msg in encrypted_messages:
            print(msg)

if __name__ == '__main__':
    main()