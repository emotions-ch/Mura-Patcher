import os
import fileinput
import shutil
import subprocess
import glob


def CVE_2022_47003(mode, dir):
    """
    A function that patches Mura CMS loginManager.cfc file for CVE-2022-47003 vulnerability.
    Prompts the user to specify the path to the loginManager.cfc file, based on the version of Mura CMS.

    Returns:
        None
    """

    sucsess = False
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
            print(f"{dir}: CVE-2022-47003, Patch successful! Good Job :3\n")
        else:
            print(f"{dir}: CVE-2022-47003, File found, but nothing changed")
    except(FileNotFoundError):
        print(f"{dir}: CVE-2022-47003, FileNotFoundError: This means the file is not found\n")


def CVE_2021_44906(mode, dir):
    sucsess = False
    """
    A function that patches package-lock.json file for CVE-2021-44906 vulnerability.
    Prompts the user to specify the path to the package-lock.json file.

    Returns:
        None
    """
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
            print(f"{dir}: CVE-2021-44906, Patch successful! Good Job :3\n")
        else:
            print(f"{dir}: CVE-2021-44906, File found, but nothing changed")
    except(FileNotFoundError):
        print(f"{dir}: CVE-2021-44906, FileNotFoundError: This means the file is not found\n")


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
                        return "7.4"
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
        None
    """
    success = False

    # Get the current script directory to find patches
    script_dir = os.path.dirname(os.path.abspath(__file__))
    patches_dir = os.path.join(script_dir, "patches")

    if not os.path.exists(patches_dir):
        print(f"{project_dir}: Patch files directory not found at {patches_dir}")
        return

    # Detect version if not provided
    if not version:
        version = detect_mura_version(project_dir)
        if not version:
            if mode == "man":
                version = input(f"Could not auto-detect Mura version for {project_dir}. Please enter version (7.2/7.3/7.4): ")

            else:
                print(f"{project_dir}: Could not detect Mura version, skipping patch application")
                return

    version_patches_dir = os.path.join(patches_dir, version)
    if not os.path.exists(version_patches_dir):
        print(f"{project_dir}: No patches found for version {version}")
        return

    # Find all .diff files in the version directory
    patch_files = glob.glob(os.path.join(version_patches_dir, "*.diff"))

    if not patch_files:
        print(f"{project_dir}: No patch files found for version {version}")
        return

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
                print(f"    ✓ Patch {patch_name} applied successfully")
                success = True
            else:
                print(f"    ✗ Failed to apply patch {patch_name}")
                print(f"    Error: {result.stderr}")

                # Try with different options if first attempt fails
                result2 = subprocess.run(
                    ["git", "apply", "--reject", "--ignore-space-change", patch_file],
                    cwd=project_root,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result2.returncode == 0:
                    print(f"    ✓ Patch {patch_name} applied with rejects (manual review needed)")
                    success = True
                else:
                    print(f"    ✗ Patch {patch_name} failed completely")

        except subprocess.TimeoutExpired:
            print(f"    ✗ Timeout applying patch {patch_name}")
        except Exception as e:
            print(f"    ✗ Error applying patch {patch_name}: {str(e)}")

    if success:
        print(f"{project_dir}: Patch application completed! Some patches may require manual review.\n")
    else:
        print(f"{project_dir}: No patches were successfully applied\n")


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
        for item in os.listdir(cwd):
            if os.path.isdir(os.path.join(cwd, item)):
                if patch_choice == 1:
                    CVE_2022_47003("auto", item)
                elif patch_choice == 2:
                    CVE_2021_44906("auto", item)
                elif patch_choice == 3:
                    apply_patch_files("auto", item)
                elif patch_choice == 0:
                    CVE_2021_44906("auto", item)
                    CVE_2022_47003("auto", item)
                    apply_patch_files("auto", item)
