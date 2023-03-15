import os
import fileinput
import shutil


def CVE_2022_47003(mode, dir):
    """
    A function that patches Mura CMS loginManager.cfc file for CVE-2022-47003 vulnerability.
    Prompts the user to specify the path to the loginManager.cfc file, based on the version of Mura CMS.

    Returns:
        None
    """
    if mode == "man":
        version = input('Are you running Mura 7.0.x or later (Y/N/C)')
        textToSearch = "if ( !len(arguments.userHash) || arguments.userHash == rsUser.userHash ) {"
        textToReplace = "if ( len(arguments.userid) && len(arguments.userHash) && arguments.userHash == rsUser.userHash ) {"

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
            print("Patch successful! Good Job :3\n")
        else:
            print("File found, but nothing changed")
    except(FileNotFoundError):
        print("FileNotFoundError: This means the file is not found\n")


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
            print("Patch successful! Good Job :3\n")
        else:
            print("File found, but nothing changed")
    except(FileNotFoundError):
        print("FileNotFoundError: This means the file is not found\n")


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
        "|   |   |   |   |   __ |   _   |    |   __ |   _   |_     _|      |   |   |_     _|    |  |   _   |_     _|       |   __ \ ")
    print(
        "|       |   |   |      |       |    |    __|       | |   | |   ---|       |_|   |_|       |       | |   | |   -   |      <")
    print(
        "|__|_|__|_______|___|__|___|___|    |___|  |___|___| |___| |______|___|___|_______|__|____|___|___| |___| |_______|___|__|")
    print("\n")


title()

mode = ""
while mode != "man" and mode != "auto":
    mode = input("Which mode do u want to run the script in?\n>bulk-patcher from /home [1]\n>single mode from /wwwroot [2]: \n")
    if mode != "1" and mode != "1":
        print("Invalid Mode\n")
    elif mode == "2":
        while True:
            try:
                patch = int(input("Which Patch would you like to apply?\n"
                                  ">CVE-2022-47003 and CVE-2022-47002: Authentication Bypass Vulnerability[1]\n"
                                  ">CVE-2021-44906: Prototype Pollution via Minimist[2]\n"
                                  ">All[0]:\n"))
            except(ValueError):
                print("Invalid Input")

            if patch == 1:
                CVE_2022_47003("man", None)
            elif patch == 2:
                CVE_2021_44906("man", None)
            elif patch == 0:
                CVE_2021_44906("man", None)
                CVE_2022_47003("man", None)
    elif mode == "1":
        # Get the current working directory
        cwd = os.getcwd()
        # Iterate over all items in the directory
        for item in os.listdir(cwd):
            # Check if the item is a folder
            if os.path.isdir(os.path.join(cwd, item)):
                # If it is, print its name
                CVE_2021_44906("auto", item)
                CVE_2022_47003("auto", item)
