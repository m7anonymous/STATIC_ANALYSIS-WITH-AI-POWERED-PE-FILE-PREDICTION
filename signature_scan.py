import yara
import os

rule_files = {}

for file in os.listdir("rules"):

    if file.endswith(".yar"):

        path = os.path.join("rules", file)

        try:
            yara.compile(filepath=path)

            rule_name = file.replace(".yar", "")

            rule_files[rule_name] = path

            print(f"[OK] {file}")

        except Exception as e:

            print(f"[ERROR] {file} -> {e}")


rules = yara.compile(filepaths=rule_files)

print("\n[+] Working rules loaded!")


def signature_scan(file_path):

    matches = rules.match(file_path)

    return matches
