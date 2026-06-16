import os
import yaml

from packaging import version

OSV_PATH = "osv/vulns"


def search_package(package_name, installed_version=None):

    package_vulnerable = False
    print(f"\n[DEBUG] package_name = {package_name}")
    package_folder = os.path.join(OSV_PATH, package_name)

    # =========================
    # CHECK IF PACKAGE EXISTS
    # =========================

    if not os.path.exists(package_folder):

        print(f"[INFO] No advisories found for {package_name}")

        return

    print(f"\n[+] Searching advisories for: {package_name}")

    # =========================
    # READ YAML FILES
    # =========================

    for root, dirs, files in os.walk(package_folder):

        for file in files:

            if file.endswith(".yaml") or file.endswith(".yml"):

                file_path = os.path.join(root, file)

                try:

                    with open(file_path, "r") as f:

                        advisory = yaml.safe_load(f)

                    # =========================
                    # EXTRACT INFO
                    # =========================

                    advisory_id = advisory.get("id", "N/A")

                    aliases = advisory.get("aliases", [])

                    details = advisory.get("details", "No details")

                    affected = advisory.get("affected", [])

                    fixed_versions = []
                    vulnerable = False

                    for item in affected:

                        ranges = item.get("ranges", [])

                        for r in ranges:

                            events = r.get("events", [])

                            for event in events:

                                if "fixed" in event:

                                    val = event["fixed"]

                # ONLY keep real version strings
                                    try:
                                        version.parse(val)
                                        fixed_versions.append(val)
                                    except:
                                           pass
                    print("\n--------------------------------")

                    print(f"Advisory ID: {advisory_id}")

                    print(f"Aliases/CVE: {aliases}")

                    print(f"Details: {details[:200]}")


                    for fv in fixed_versions:
                        print(f"Fixed Version: {fv}")

                    if installed_version:

                       for fv in fixed_versions:

                           try:
                               if installed_version < version.parse(fv):
                                  vulnerable = True
                                  break
                           except:
                                  pass

                       if vulnerable:
                            print("🚨 STATUS: VULNERABLE ")
                       else:
                            print("🟢 STATUS: SAFE (for this advisory)")

                except Exception as e:
                          print(f"[ERROR] Failed reading {file}: {e}")

print("\n==== OSV CHECKER ====")

print("1. Manual package search")
print("2. Scan requirements.txt")

choice = input("\nEnter choice: ")

if choice == "1" :
   package_name = input("Enter the package name you would like to parse:")
   package_version = input("Enter Version (eg 2.0): ")
   installed_version = version.parse(package_version)
   search_package(package_name, installed_version)

elif choice == "2":

    requirements_path = "samples/requirements.txt"

    try:

        with open(requirements_path, "r") as f:

            lines = f.readlines()

        for line in lines:

            line = line.strip()

            if "==" in line:

                parts = line.split("==")
                package_name = parts[0]
                package_version = parts[1]

                installed_version = version.parse(package_version)

                print(f"\nPackage: {package_name}")
                print(f"Version: {package_version}")

                search_package(package_name, installed_version)

    except Exception as e:

        print(f"[ERROR] Failed reading requirements.txt: {e}")

