import os
import fileinput
import shutil


def CVE_2022_47003():
    """
    A function that patches Mura CMS loginManager.cfc file for CVE-2022-47003 vulnerability.
    Prompts the user to specify the path to the loginManager.cfc file, based on the version of Mura CMS.

    Returns:
        None
    """
    version = input('Are you running Mura 7.0.x or later (Y/N/C)')

    textToSearch = "if ( !len(arguments.userHash) || arguments.userHash == rsUser.userHash ) {"
    textToReplace = "if ( len(arguments.userid) && len(arguments.userHash) && arguments.userHash == rsUser.userHash ) {"

    if version == "Y":
        patchpath = "core/mura/login/loginManager.cfc"
    elif version == "N":
        patchpath = "requirements/mura/login/loginManager.cfc"
    else:
        patchpath = input("Specify the path to loginManager.cfc")

    try:
        shutil.copy(patchpath, f'{patchpath}.bak')
        with fileinput.FileInput(patchpath, inplace=True, backup='.bak') as file:
            for line in file:
                print(line.replace(textToSearch, textToReplace), end='')
        print("Patch successful! Good Job :3\n")
    except(FileNotFoundError):
        print("FileNotFoundError: This means the file is not found\n")


def CVE_2021_44906():
    """
    A function that patches package-lock.json file for CVE-2021-44906 vulnerability.
    Prompts the user to specify the path to the package-lock.json file.

    Returns:
        None
    """
    patchpath = input("Specify the path to package-lock.json, leave empty for default: ")
    if patchpath == "":
        patchpath = "core/modules/v1/cta/package-lock.json"

    try:
        shutil.copy(patchpath, f'{patchpath}.bak')
        # Open the file for reading
        with open(patchpath, 'r') as file:
            # Read in the file as a list of lines
            lines = file.readlines()
            isFound = False

        # Iterate over the lines and replace the next 3 lines after "minimist": {
        for i in range(len(lines)):
            if '    "minimist": {' in lines[i] and isFound == False:
                # Replace the next 3 lines with the new lines
                lines[i + 1] = '      "version": "1.2.8",\n'
                lines[i + 2] = '      "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.8.tgz",\n'
                lines[
                    i + 3] = '      "integrity": "sha512-2yyAR8qBkN3YuheJanUpWC5U3bb5osDywNB8RzDVlDwDHbocAJveqqj1u8+SVD7jkWT4yvsHCpWqqWqAxb0zCA==",\n'
                isFound = True

        # Open the file for writing and write the modified lines back to it
        with open(patchpath, 'w') as file:
            file.writelines(lines)

        print("Patch successful! Good Job :3\n")
    except(FileNotFoundError):
        print("FileNotFoundError: This means the file is not found\n")


def menue():
    """
    A function that prints the main menu title on the screen.

    Args:
        None

    Returns:
        None
    """
    print(
        " __       __  __    __  _______    ______         _______    ______   ________  ______   __    __  ______  __    __   ______   ________  ______   _______  ")
    print(
        "/  \     /  |/  |  /  |/       \  /      \       /       \  /      \ /        |/      \ /  |  /  |/      |/  \  /  | /      \ /        |/      \ /       \ ")
    print(
        "$$  \   /$$ |$$ |  $$ |$$$$$$$  |/$$$$$$  |      $$$$$$$  |/$$$$$$  |$$$$$$$$//$$$$$$  |$$ |  $$ |$$$$$$/ $$  \ $$ |/$$$$$$  |$$$$$$$$//$$$$$$  |$$$$$$$  |")
    print(
        "$$$  \ /$$$ |$$ |  $$ |$$ |__$$ |$$ |__$$ |      $$ |__$$ |$$ |__$$ |   $$ |  $$ |  $$/ $$ |__$$ |  $$ |  $$$  \$$ |$$ |__$$ |   $$ |  $$ |  $$ |$$ |__$$ |")
    print(
        "$$$$  /$$$$ |$$ |  $$ |$$    $$< $$    $$ |      $$    $$/ $$    $$ |   $$ |  $$ |      $$    $$ |  $$ |  $$$$  $$ |$$    $$ |   $$ |  $$ |  $$ |$$    $$< ")
    print(
        "$$ $$ $$/$$ |$$ |  $$ |$$$$$$$  |$$$$$$$$ |      $$$$$$$/  $$$$$$$$ |   $$ |  $$ |   __ $$$$$$$$ |  $$ |  $$ $$ $$ |$$$$$$$$ |   $$ |  $$ |  $$ |$$$$$$$  |")
    print(
        "$$ |$$$/ $$ |$$ \__$$ |$$ |  $$ |$$ |  $$ |      $$ |      $$ |  $$ |   $$ |  $$ \__/  |$$ |  $$ | _$$ |_ $$ |$$$$ |$$ |  $$ |   $$ |  $$ \__$$ |$$ |  $$ |")
    print(
        "$$ | $/  $$ |$$    $$/ $$ |  $$ |$$ |  $$ |      $$ |      $$ |  $$ |   $$ |  $$    $$/ $$ |  $$ |/ $$   |$$ | $$$ |$$ |  $$ |   $$ |  $$    $$/ $$ |  $$ |")
    print(
        "$$/      $$/  $$$$$$/  $$/   $$/ $$/   $$/       $$/       $$/   $$/    $$/    $$$$$$/  $$/   $$/ $$$$$$/ $$/   $$/ $$/   $$/    $$/    $$$$$$/  $$/   $$/ ")
    print("\n\n")


menue()
while True:
    try:
        patch = int(input("Which Patch would you like to apply?\n"
                          ">CVE-2022-47003 and CVE-2022-47002: Authentication Bypass Vulnerability[1]\n"
                          ">CVE-2021-44906: Prototype Pollution via Minimist[2]\n"
                          ">All[0]:\n"))
    except(ValueError):
        print("Invalid Input")

    if patch == 1:
        CVE_2022_47003()
    elif patch == 2:
        CVE_2021_44906()
    elif patch == 0:
        CVE_2021_44906()
        CVE_2022_47003()
