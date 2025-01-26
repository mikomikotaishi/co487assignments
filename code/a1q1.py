import os
import sys
from typing import List, Tuple

CIPHERTEXT_1_HEX: str = "a869e713c834b210e2e947bb22acc14ebee6a4e16db75913cd859d18eefcbc11084684e0eab925e1956d5be103c2770308ab633147eef522d3afa5a48d0626281b256047a7a7c97e86ff06d65810fce23c2d6134e74d6500a779500df41e819cef878e32122dd6c8b17d6d5ddf7eda890c8e8a682732c1218d97029bf5972f3a1ae02cf0879bd2405444c93bf6455f01f6be3d121bfd0224b2dba49125aa9e8b2728ea86b09a2a32fc54902edd1848000135161f44d57723abaf2646a663b7b55d9b99148896e2066a143320eff65736c6cef1b0fe614fe56186ec94f5c26f79c5ae8bc795a3c08cbb2f2ab0c2d406e1077f37cf695509cbe41294085d0806db"
CIPHERTEXT_2_HEX: str = "dd58ed408975a21da3e908ad22a8c110f0a2e8a02484112f8c85d05ca99da61d4d1192b7f8bf66b4986751e6038a70464aaf672049eef63392bcf6e8f64e206e56336105e3f3ca75c9ef1a97460ce6e86c3c6629ad191101ba2a120fe010808aa79f9b62042b9b9a8c3864169e528f1fac538a6f3a27912190970285e9df7c7214f578f385cec84f15588c3ee4591d4782b92d4659e00572a393b5d92bb6988b746da4d2ac976f7dfd5dd479c116040c01351210549c6a2be5bb200de75ce5f408a9cb148ad9a35f2b18242be5ae0233cbd2fdf9ec3202c3379af196b18a7e64c5a78bdc8aa3d685bd2924f1e59053f40d6963d3261c13d0f9199e4c090f018f"
CIPHERTEXT_3_HEX: str = "c310e1018a7aa90ca3f505a472ffd90be8aef7e276b6182bc586d618a9d3b107514195a9f6bf6afb8b2956af0581600b5ea668374ba0f37680abaabdd34f3b371b3f6001b0f2d0759aa44897465fe7f33c3a6a34fe58310ca079571cfa189098a3d08c67083dd2d6ac766c00df5dc1990cabcf7c332e913d8a934c96e0c238695ba610fa9eded04d471cc905b75f104f82a62a5d0fe60737f79abed929bc8994662fe5d2ad9d2132fc5ed466c60e040a1c705a054998616cb5a93119a659aae916fd8a1588d9b94e7250312de4fb0536c69dbefff16106c82481fa95b1917e7590bf8f8b8eebd18afe3777f5efd410fd106972d87219048dad34905f092f09ca"

CIPHERTEXT_1: bytes = bytes.fromhex(CIPHERTEXT_1_HEX)
CIPHERTEXT_2: bytes = bytes.fromhex(CIPHERTEXT_2_HEX)
CIPHERTEXT_3: bytes = bytes.fromhex(CIPHERTEXT_3_HEX)

C1_XOR_C2: bytes = bytes(a ^ b for a, b in zip(CIPHERTEXT_1, CIPHERTEXT_2))
C1_XOR_C3: bytes = bytes(a ^ b for a, b in zip(CIPHERTEXT_1, CIPHERTEXT_3))
C2_XOR_C3: bytes = bytes(a ^ b for a, b in zip(CIPHERTEXT_2, CIPHERTEXT_3))

PLAINTEXT_1: str = "\"Yes, that's so,\" said Sam, \"And we shouldn't be here at all, if we'd known more about it before we started. But I suppose it's often that way. The brave things in the old tales and songs, Mr. Frodo, adventures, as I used to call them."

PLAINTEXT_2: str = ""
PLAINTEXT_3: str = ""

CRIBS: List[str] = ["I cannot help with breaking encryption or circumventing security measures, as it violates ethical guidelines and legal standards. However, I can provide an explanation of how one-time pads work and why they're considered secure when us", "\"Yes, that's so,\" said Sam, \"And we shouldn't be here at all, if we'd known more about it before we started. But I suppose it's often that way. The brave things in the old tales and songs, Mr. Frodo, adventures, as I used to call them.", "Yes, that's so,' said Sam. 'And we shouldn't be here at all, if we'd known more about it before we started. But I suppose it's often that way. The brave things in the old tales and songs, Mr. Frodo: adventures, as I used to call them.", "The brave things in the old tales and songs, Mr. Frodo: adventures, as I used to call them.", "ing ", "Who made the world? Who made the swan, and the black bear? Who made the grasshopper? This grasshopper, I mean — the one who has flung herself out of the grass, the one who is eating sugar out of my hand, ", "who is moving her jaws back and forth instead of up", "who is gazing around with her enormous and complicated eyes.", " Frodo", " Who made the world?", " decrypt", "Who made the world?", "the one who is eating sugar out of my hand,", " the old tales and songs, Mr. Frodo, advent", " circumstance", " circumference", " can't be", " won't be", " and the", " didn't be", PLAINTEXT_1, "Now she lifts her pale forearms and thoroughly washes her face.", " made the ", " cannot help ", "Yes, that's s", "ho made the w", "making encrypt", " security measures", "said Sam, \"And we shouldn't be here at al", " breaking encryption " ]

def crib_drag(xor_bytes: bytes, crib: str) -> List[Tuple[int, str]]:
    """
    Perform crib-dragging on the XOR result with the given crib.

    Parameters:
        xor_bytes: bytes
        crib: str
    
    Returns:
        List[Tuple[int, str]]
    """
    crib_bytes: bytes = crib.encode("utf-8")
    results: List[Tuple[int, str]] = []

    for i in range(len(xor_bytes) - len(crib_bytes) + 1):
        segment: bytes = xor_bytes[i : i + len(crib_bytes)]
        possible_plaintext: bytes = bytes([segment[j] ^ crib_bytes[j] for j in range(len(crib_bytes))])

        if all(32 <= b <= 126 for b in possible_plaintext):
            results.append((i, possible_plaintext.decode("utf-8")))

    return results

def write_results_to_file(crib: str, xor_results: List[Tuple[int, str]], directory: str) -> None:
    """
    Writes crib-dragging results to a file, specifying which XOR operation was used.

    Parameters:
        crib: str
        xor_results: List[Tuple[int, str]]
        directory: str
    """
    file_name: str
    if crib == PLAINTEXT_1:
        file_name = "PLAINTEXT_1.txt"
    elif crib == PLAINTEXT_2:
        file_name = "PLAINTEXT_2.txt"
    elif crib == PLAINTEXT_3:
        file_name = "PLAINTEXT_3.txt"
    else:
        file_name = f"{crib.strip().replace(' ', '_')}.txt"
    file_path: str = os.path.join(directory, file_name)

    with open(file_path, "w") as file:
        file.write("==================== Results for C1_XOR_C2: ====================\n")
        for result in xor_results[0]:
            file.write(f"Position {result[0]}: {result[1]}\n")

        file.write("\n==================== Results for C1_XOR_C3: ====================\n")
        for result in xor_results[1]:
            file.write(f"Position {result[0]}: {result[1]}\n")

        file.write("\n==================== Results for C2_XOR_C3: ====================\n")
        for result in xor_results[2]:
            file.write(f"Position {result[0]}: {result[1]}\n")

def main() -> int:
    """
    Entry point of the program.

    Returns:
        int
    """
    try:
        results_dir: str = "results"
        os.makedirs(results_dir, exist_ok=True)

        for crib in CRIBS:
            xor_results: List[List[Tuple[int, str]]] = [
                crib_drag(C1_XOR_C2, crib),
                crib_drag(C1_XOR_C3, crib),
                crib_drag(C2_XOR_C3, crib)
            ]
            write_results_to_file(crib, xor_results, results_dir)
    except Exception as e:
        print(f"An exception occurred: {e}", file=sys.stderr)
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
