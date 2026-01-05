import os
import fileinput
import shutil
import subprocess
import glob
import csv
import datetime


def log_patch_result(csv_filename, project_name, project_path, mura_version, cve_2021_44906_result, cve_2021_44906_output, cve_2022_47003_result, cve_2022_47003_output, git_patches_result, git_patches_output, overall_success):
    """
    Log patch results to a CSV file with separate columns for each action.

    Args:
        csv_filename (str): Name of the CSV file to write to
        project_name (str): Name of the project directory
        project_path (str): Full path to the project
        mura_version (str): Detected Mura version or 'Unknown'
        cve_2021_44906_result (str): Result of CVE-2021-44906 patch ('Success', 'Failed', 'Not Applied')
        cve_2021_44906_output (str): Output message from CVE-2021-44906 patch
        cve_2022_47003_result (str): Result of CVE-2022-47003 patch ('Success', 'Failed', 'Not Applied')
        cve_2022_47003_output (str): Output message from CVE-2022-47003 patch
        git_patches_result (str): Result of git patch files ('Success', 'Failed', 'Not Applied')
        git_patches_output (str): Output message from git patch files
        overall_success (bool): Overall success status
    """
    file_exists = os.path.exists(csv_filename)

    with open(csv_filename, 'a', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['timestamp', 'project_name', 'project_path', 'mura_version',
                     'cve_2021_44906_result', 'cve_2021_44906_output',
                     'cve_2022_47003_result', 'cve_2022_47003_output',
                     'git_patches_result', 'git_patches_output',
                     'overall_success']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Write header if file is new
        if not file_exists:
            writer.writeheader()

        writer.writerow({
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'project_name': project_name,
            'project_path': project_path,
            'mura_version': mura_version or 'Unknown',
            'cve_2021_44906_result': cve_2021_44906_result,
            'cve_2021_44906_output': cve_2021_44906_output,
            'cve_2022_47003_result': cve_2022_47003_result,
            'cve_2022_47003_output': cve_2022_47003_output,
            'git_patches_result': git_patches_result,
            'git_patches_output': git_patches_output,
            'overall_success': overall_success
        })


def CVE_2022_47003(mode, dir):
    """
    A function that patches Mura CMS loginManager.cfc file for CVE-2022-47003 vulnerability.
    Prompts the user to specify the path to the loginManager.cfc file, based on the version of Mura CMS.

    Returns:
        tuple: (bool, str) - (success status, output message)
    """

    sucsess = False
    output_msg = ""
    textToSearch = "if ( !len(arguments.userHash) || arguments.userHash == rsUser.userHash ) {"
    textToReplace = "if ( len(arguments.userid) && len(arguments.userHash) && arguments.userHash == rsUser.userHash ) {"
    if mode == "man":
        version = input('Are you running Mura 7.0.x or later (Y/N/C)')

        if version == "Y":
            patchpath = "core/mura/login/loginManager.cfc"
        elif version == "N":
            patchpath = "requirements/mura/login/loginManager.cfc"
        else:
            patchpath = input("Specify the path to loginManager.cfc")
    elif mode == "auto":
        if os.path.exists(f"{dir}/wwwroot/core/mura/login/loginManager.cfc"):
            patchpath = f"{dir}/wwwroot/core/mura/login/loginManager.cfc"

        elif os.path.exists(f"{dir}/wwwroot/requirements/mura/login/loginManager.cfc"):
            patchpath = f"{dir}/wwwroot/requirements/mura/login/loginManager.cfc"

        elif os.path.exists(f"{dir}/Site/core/mura/login/loginManager.cfc"):
            patchpath = f"{dir}/Site/core/mura/login/loginManager.cfc"

        elif os.path.exists(f"{dir}/Site/requirements/mura/login/loginManager.cfc"):
            patchpath = f"{dir}/Site/requirements/mura/login/loginManager.cfc"
        else:
            patchpath = "core/mura/login/loginManager.cfc"

    try:
        shutil.copy(patchpath, f'{patchpath}.bak')
        with fileinput.FileInput(patchpath, inplace=True, backup='.bak') as file:
            for line in file:
                print(line.replace(textToSearch, textToReplace), end='')
                sucsess = True

        if sucsess:
            output_msg = f"CVE-2022-47003 patch applied successfully to {patchpath}"
            print(f"{dir}: CVE-2022-47003, Patch successful! Good Job :3\n")
            return True, output_msg
        else:
            output_msg = f"CVE-2022-47003 file found at {patchpath}, but no changes were made"
            print(f"{dir}: CVE-2022-47003, File found, but nothing changed")
            return False, output_msg
    except(FileNotFoundError):
        output_msg = f"CVE-2022-47003 FileNotFoundError: loginManager.cfc not found at expected locations"
        print(f"{dir}: CVE-2022-47003, FileNotFoundError: This means the file is not found\n")
        return False, output_msg


def CVE_2021_44906(mode, dir):
    """
    A function that patches package-lock.json file for CVE-2021-44906 vulnerability.
    Prompts the user to specify the path to the package-lock.json file.

    Returns:
        tuple: (bool, str) - (success status, output message)
    """
    sucsess = False
    output_msg = ""
    if mode == "man":
        patchpath = input("Specify the path to package-lock.json, leave empty for default: ")
        if patchpath == "":
            patchpath = "core/modules/v1/cta/package-lock.json"
    elif mode == "auto":
        if os.path.exists(f"{dir}/wwwroot/core/modules/v1/cta/package-lock.json"):
            patchpath = f"{dir}/wwwroot/core/modules/v1/cta/package-lock.json"
        if os.path.exists(f"{dir}/Site/core/modules/v1/cta/package-lock.json"):
            patchpath = f"{dir}/Site/core/modules/v1/cta/package-lock.json"
        else:
            patchpath = "core/modules/v1/cta/package-lock.json"

    try:
        shutil.copy(patchpath, f'{patchpath}.bak')
        # Open the file for reading
        with open(patchpath, 'r') as file:
            # Read in the file as a list of lines
            lines = file.readlines()

        # Iterate over the lines and replace the next 3 lines after "minimist": {
        for i in range(len(lines)):
            if '    "minimist": {' in lines[i] and sucsess == False:
                # Replace the next 3 lines with the new lines
                lines[i + 1] = '      "version": "1.2.8",\n'
                lines[i + 2] = '      "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz",\n'
                lines[
                    i + 3] = '      "integrity": "sha512-2yyAR8qBkN3YuheJanUpWC5U3bb5osDywNB8RzDVlDwDHbocAJveqqj1u8+SVD7jkWT4yvsHCpWqqWqAxb0zCA==",\n'
                sucsess = True

        # Open the file for writing and write the modified lines back to it
        with open(patchpath, 'w') as file:
            file.writelines(lines)

        if sucsess:
            output_msg = f"CVE-2021-44906 patch applied successfully to {patchpath}, minimist updated to 1.2.8"
            print(f"{dir}: CVE-2021-44906, Patch successful! Good Job :3\n")
            return True, output_msg
        else:
            output_msg = f"CVE-2021-44906 file found at {patchpath}, but minimist section not found or already patched"
            print(f"{dir}: CVE-2021-44906, File found, but nothing changed")
            return False, output_msg
    except(FileNotFoundError):
        output_msg = f"CVE-2021-44906 FileNotFoundError: package-lock.json not found at expected locations"
        print(f"{dir}: CVE-2021-44906, FileNotFoundError: This means the file is not found\n")
        return False, output_msg


def detect_mura_version(project_dir):
    """
    Detect the Mura CMS version by checking for version-specific files or content.

    Args:
        project_dir (str): Path to the project directory

    Returns:
        str: Detected version (7.2, 7.3, 7.4) or None if not detected
    """
    # Check package-lock.json first for version info
    for root_candidate in ["", "wwwroot", "Site"]:
        base_path = os.path.join(project_dir, root_candidate) if root_candidate else project_dir
        package_lock_path = os.path.join(base_path, "package-lock.json")

        if os.path.exists(package_lock_path):
            try:
                import json
                with open(package_lock_path, 'r', encoding='utf-8') as f:
                    package_data = json.load(f)
                    version = package_data.get("version", "")
                    if version.startswith("7.5"):
                        return "7.5"
                    elif version.startswith("7.4"):
                        return "7.4"
                    elif version.startswith("7.3"):
                        return "7.3"
                    elif version.startswith("7.2"):
                        return "7.2"
            except Exception:
                continue
    return None


def apply_patch_files(mode, project_dir, version=None):
    """
    Apply patch files from the patches directory to a Mura CMS project.

    Args:
        mode (str): "man" for manual mode, "auto" for automatic mode
        project_dir (str): Path to the project directory
        version (str): Mura version (7.2, 7.3, 7.4) - auto-detected if None

    Returns:
        tuple: (bool, str) - (success status, output message)
    """
    success = False
    output_messages = []

    # Get the current script directory to find patches
    script_dir = os.path.dirname(os.path.abspath(__file__))
    patches_dir = os.path.join(script_dir, "patches")

    if not os.path.exists(patches_dir):
        print(f"{project_dir}: Patch files directory not found at {patches_dir}")
        return False

    # Detect version if not provided
    if not version:
        version = detect_mura_version(project_dir)
        if not version:
            if mode == "man":
                version = input(f"Could not auto-detect Mura version for {project_dir}. Please enter version (7.2/7.3/7.4): ")

            else:
                print(f"{project_dir}: Could not detect Mura version, skipping patch application")
                return False

    version_patches_dir = os.path.join(patches_dir, version)
    if not os.path.exists(version_patches_dir):
        print(f"{project_dir}: No patches found for version {version}")
        return False

    # Find all .diff files in the version directory
    patch_files = glob.glob(os.path.join(version_patches_dir, "*.diff"))

    if not patch_files:
        print(f"{project_dir}: No patch files found for version {version}")
        return False

    # Determine the project root (check for common Mura structures)
    project_root = project_dir
    for potential_root in ["wwwroot", "Site"]:
        potential_path = os.path.join(project_dir, potential_root)
        if os.path.exists(potential_path) and (
            os.path.exists(os.path.join(potential_path, "admin")) or
            os.path.exists(os.path.join(potential_path, "core"))
        ):
            project_root = potential_path
            break

    print(f"{project_dir}: Applying patches for Mura {version} to {project_root}")

    # Apply each patch file
    for patch_file in patch_files:
        patch_name = os.path.basename(patch_file)
        print(f"  Applying patch: {patch_name}")

        try:
            # Change to project directory and apply patch
            result = subprocess.run(
                ["git", "apply", "--ignore-space-change", "--ignore-whitespace", patch_file],
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                msg = f"Patch {patch_name} applied successfully"
                print(f"    ✓ {msg}")
                output_messages.append(msg)
                success = True
            else:
                # Try with different options if first attempt fails
                result2 = subprocess.run(
                    ["git", "apply", "--reject", "--ignore-space-change", patch_file],
                    cwd=project_root,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result2.returncode == 0:
                    msg = f"Patch {patch_name} applied with rejects (manual review needed)"
                    print(f"    ✓ {msg}")
                    output_messages.append(msg)
                    success = True
                else:
                    msg = f"Patch {patch_name} failed: {result.stderr.strip()}"
                    print(f"    ✗ {msg}")
                    output_messages.append(msg)

        except subprocess.TimeoutExpired:
            msg = f"Timeout applying patch {patch_name}"
            print(f"    ✗ {msg}")
            output_messages.append(msg)
        except Exception as e:
            msg = f"Error applying patch {patch_name}: {str(e)}"
            print(f"    ✗ {msg}")
            output_messages.append(msg)

    final_output = "; ".join(output_messages) if output_messages else "No patches found or applied"

    if success:
        print(f"{project_dir}: Patch application completed! Some patches may require manual review.\n")
    else:
        print(f"{project_dir}: No patches were successfully applied\n")

    return success, final_output


def title():
    """
    A function that prints the main menu title on the screen.

    Args:
        None

    Returns:
        None
    """

    print(
        " _______ _______ ______ _______      ______ _______ _______ ______ _______ _______ _______ _______ _______ _______ ______ ")
    print(
        "|   |   |   |   |   __ |   _   |    |   __ |   _   |_     _|      |   |   |_     _|    |  |   _   |_     _|       |   __ \\")
    print(
        "|       |   |   |      |       |    |    __|       | |   | |   ---|       |_|   |_|       |       | |   | |   -   |      <")
    print(
        "|__|_|__|_______|___|__|___|___|    |___|  |___|___| |___| |______|___|___|_______|__|____|___|___| |___| |_______|___|__|")
    print("\n")


title()

mode = ""
while mode != "man" and mode != "auto":
    mode = input(
        "Which mode do u want to run the script in?\n>bulk-patcher from /home [1]\n>single mode from /wwwroot [2]: \n")
    if mode != "1" and mode != "2":
        print("Invalid Mode\n")
    elif mode == "2":
        while True:
            try:
                patch = int(input("Which Patch would you like to apply?\n"
                                  ">CVE-2022-47003 and CVE-2022-47002: Authentication Bypass Vulnerability[1]\n"
                                  ">CVE-2021-44906: Prototype Pollution via Minimist[2]\n"
                                  ">Apply Patch Files (Git Diff)[3]\n"
                                  ">All CVEs[0]:\n"))
            except(ValueError):
                print("Invalid Input")

            if patch == 1:
                CVE_2022_47003("man", None)
            elif patch == 2:
                CVE_2021_44906("man", None)
            elif patch == 3:
                project_path = input("Enter the path to your Mura project (e.g., D:\\feusi.ag): ")
                apply_patch_files("man", project_path)
            elif patch == 0:
                CVE_2021_44906("man", None)
                CVE_2022_47003("man", None)
            exit()
    elif mode == "1":
        cwd = os.getcwd()
        patch_choice = int(input("Which Patch would you like to apply to all folders?\n"
                                ">CVE-2022-47003 and CVE-2022-47002: Authentication Bypass Vulnerability[1]\n"
                                ">CVE-2021-44906: Prototype Pollution via Minimist[2]\n"
                                ">Apply Patch Files (Git Diff)[3]\n"
                                ">All CVEs[0]:\n"))

        # Generate CSV filename with timestamp
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_filename = f"patch_results_{timestamp}.csv"

        print(f"\nStarting bulk patching. Results will be logged to: {csv_filename}\n")

        for item in os.listdir(cwd):
            print(item)
            if os.path.isdir(os.path.join(cwd, item)):
                project_path = os.path.abspath(os.path.join(cwd, item))
                mura_version = detect_mura_version(project_path)

                # Initialize results for all actions
                cve_2021_result, cve_2021_output = "Not Applied", ""
                cve_2022_result, cve_2022_output = "Not Applied", ""
                git_patches_result, git_patches_output = "Not Applied", ""

                overall_success = False

                try:
                    if patch_choice == 1:
                        success, output = CVE_2022_47003("auto", item)
                        cve_2022_result = "Success" if success else "Failed"
                        cve_2022_output = output
                        overall_success = success
                    elif patch_choice == 2:
                        success, output = CVE_2021_44906("auto", item)
                        cve_2021_result = "Success" if success else "Failed"
                        cve_2021_output = output
                        overall_success = success
                    elif patch_choice == 3:
                        success, output = apply_patch_files("auto", item)
                        git_patches_result = "Success" if success else "Failed"
                        git_patches_output = output
                        overall_success = success
                    elif patch_choice == 0:
                        # Apply all patches and track individual results
                        success1, output1 = CVE_2021_44906("auto", item)
                        success2, output2 = CVE_2022_47003("auto", item)
                        success3, output3 = apply_patch_files("auto", item)

                        cve_2021_result = "Success" if success1 else "Failed"
                        cve_2021_output = output1
                        cve_2022_result = "Success" if success2 else "Failed"
                        cve_2022_output = output2
                        git_patches_result = "Success" if success3 else "Failed"
                        git_patches_output = output3

                        overall_success = success1 or success2 or success3
                except Exception as e:
                    print(f"Error processing {item}: {str(e)}")

                # Log the result with separate columns
                log_patch_result(
                    csv_filename,
                    item,
                    project_path,
                    mura_version,
                    cve_2021_result,
                    cve_2021_output,
                    cve_2022_result,
                    cve_2022_output,
                    git_patches_result,
                    git_patches_output,
                    overall_success
                )

        print(f"\nBulk patching completed! Results logged to: {csv_filename}")
        print(f"Check the CSV file for detailed results of each project.")
