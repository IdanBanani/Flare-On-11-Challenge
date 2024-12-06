import hashlib
import zlib
import string

ascii_printable = string.printable.encode()

# Constants for hash conditions
FLAG_LENGTH = 85
# ASCII_RANGE = range(32, 126)

# Predefinced hashes dictionary
HASHES = {
    "crc32": [
        (8, "61089c5c"),
        (34, "5888fc1b"),
        (63, "66715919"),
        (78, "7cab8d64"),
    ],
    "sha256": [
        (14, "403d5f23d149670348b147a15eeb7010914701a7e99aad2e43f90cfa0325c76f"),
        (56, "593f2d04aab251f60c9e4b8bbc1e05a34e920980ec08351a18459b2bc7dbf2f6"),
    ],
    "md5": [
        (0, "89484b14b36a8d5329426a3d944d2983"),
        (50, "657dae0913ee12be6fb2a6f687aae1c7"),
        (76, "f98ed07a4d5f50f7de1410d905f1477f"),
        (32, "738a656e8e8ec272ca17cd51e12f558b"),
    ],
}


def load_conditions(filename):
    with open(filename, "r") as file:
        conditions = [line.strip() for line in file if line.strip()]
    return conditions


# Function to compute hashes
def compute_hash(flag, offset, length, hash_type):

    byte_data = flag[offset : offset + length]
    if hash_type == "md5":
        return hashlib.md5(byte_data).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(byte_data).hexdigest()
    elif hash_type == "crc32":
        return "%08x" % (zlib.crc32(byte_data) & 0xFFFFFFFF)
    else:
        raise ValueError(f"Unknown hash type: {hash_type}")


def solve_arithmetic(res, index, val, op):
    if op == "+":
        return res - val
    elif op == "-":
        return res + val
    elif op == "^":
        return res ^ val


def parse_condition(condition):
    res, index = None, None
    try:
        res = int(condition.split("==")[-1].lstrip())
        index = int(condition.split("(")[-1].split(")")[0])
    except:
        pass
    if "+" in condition:
        val = int(condition.split("+")[-1].split("==")[0].strip())
        return (
            solve_arithmetic(res, index, val, "+"),
            index,
            "uint8" if "uint8" in condition else "uint32",
        )
    elif "-" in condition:
        val = int(condition.split("-")[-1].split("==")[0].strip())
        return (
            solve_arithmetic(res, index, val, "-"),
            index,
            "uint8" if "uint8" in condition else "uint32",
        )
    elif "^" in condition:
        val = int(condition.split("^")[-1].split("==")[0].strip())
        return (
            solve_arithmetic(res, index, val, "^"),
            index,
            "uint8" if "uint8" in condition else "uint32",
        )
    return res, index, None  # for non-arithmetic conditions


def main():
    flag = bytearray(FLAG_LENGTH)
    # Brute-force logic
    for hash_type, conditions in HASHES.items():
        for index, expected_hash in conditions:
            found = False  

            for i in ascii_printable:
                for j in ascii_printable:
                    sequence = bytes([i]) + bytes([j])
                    if compute_hash(sequence, 0, 2, hash_type) == expected_hash:
                        flag[index] = i
                        flag[index + 1] = j
                        found = True
                        break  

                if found:
                    break  

            if not found:
                print(f"Failed to find match for hash: {expected_hash}")

    conditions = load_conditions("conditions.txt")
    for condition in conditions:
        if "==" in condition:
            res, index, data_type = parse_condition(condition)
            if data_type == "uint8":
                flag[index] = res & 0xFF  # Store the result as uint8
            elif data_type == "uint32":
                flag[index : index + 4] = [
                    res & 0xFF,
                    (res >> 8) & 0xFF,
                    (res >> 16) & 0xFF,
                    (res >> 24) & 0xFF,
                ]  # Store as 4 bytes

    # Final verification for the MD5 condition
    MD5_HASH_0_FILESZ = "b7dc94ca98aa58dabb5404541c812db2"
    if compute_hash(flag, 0, FLAG_LENGTH, "md5") == MD5_HASH_0_FILESZ:
        print("Final flag is valid:", flag)
    else:
        print("Final flag is invalid:", "".join(flag))


if __name__ == "__main__":
    main()
