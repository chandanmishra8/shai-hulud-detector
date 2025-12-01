import argparse
from json import load

import pandas as pd
from packaging import version as pkg_version


def create_row(package_name, package_version):
    """
    Creates a dictionary row for a package with its name and version.

    Parameters:
    package_name (str): The name of the package.
    package_version (str): The version of the package.

    Returns:
    dict: A dictionary with keys 'Package' and 'Version'.
    """
    return {
        "Package": package_name,
        "Version": package_version,
    }


def load_compromised_packages_csv(url):
    """
    Loads a CSV file containing compromised packages and returns a DataFrame.

    Parameters:
    url (str): The URL to the compromised packages CSV.

    Returns:
    pd.DataFrame: DataFrame with columns 'Package' and 'Version' for compromised packages.
    """
    rows = []
    df = pd.read_csv(url, header=0)
    print(f"Comparing against known vulnerable packages found on the internet: {len(df)} ({url})")
    for _, row in df.iterrows():
        package = row['Package']
        versions = str(row['Version']).split('||')
        for version_str in versions:
            version_str = version_str.replace("=", "").strip()
            rows.append(create_row(package, version_str))
    return pd.DataFrame(rows)


def load_package_lock_json(path):
    """
    Loads a package-lock.json file and extracts installed packages and their versions.

    Parameters:
    path (str): Path to the package-lock.json file.

    Returns:
    pd.DataFrame: DataFrame with columns 'Package' and 'Version' for installed packages.
    """
    rows = []
    with open(path, "r") as file_:
        package_lock_json = load(file_)
        packages = package_lock_json.get('packages', {})
        for pkg_path, info in packages.items():
            if not pkg_path or pkg_path == "":
                continue
            if info.get("version") and pkg_path.count("node_modules") <= 1:
                pkg_name = pkg_path.replace('node_modules/', '')
                rows.append(create_row(pkg_name, info.get('version', "None")))
            for k, v in info.get('dependencies', {}).items():
                rows.append(create_row(k, v))

    print(f"Total Packages found in package-lock.json: {len(rows)}")
    return pd.DataFrame(rows)


def version_satisfies(installed, requirement):
    """
    Checks if the installed version satisfies the requirement.

    Parameters:
    installed (str): The installed version string.
    requirement (str): The required version string.

    Returns:
    bool: True if the installed version matches the requirement, False otherwise.
    """
    requirement = requirement.strip()
    try:
        return pkg_version.parse(installed) == pkg_version.parse(requirement)
    except Exception as e:
        print(e)
        return False


def find_common_packages(compromised_df, installed_df, check_version):
    """
    Finds packages common between compromised and installed packages.

    Parameters:
    compromised_df (pd.DataFrame): DataFrame of compromised packages.
    installed_df (pd.DataFrame): DataFrame of installed packages.
    check_version (str): If "true", checks both package name and version; else only package name.

    Returns:
    pd.DataFrame: DataFrame of common packages found.
    """
    if check_version == "true":
        compromised_df["Version_parsed"] = compromised_df["Version"].apply(lambda v: v.lstrip("=~^"))
        installed_df["Version_parsed"] = installed_df["Version"].apply(lambda v: v.lstrip("=~^"))

        rows = []
        for _, row1 in compromised_df.iterrows():
            pkg_name = row1["Package"]
            ver1 = row1["Version_parsed"].strip("=~^")
            for _, row2 in installed_df[installed_df["Package"] == pkg_name].iterrows():
                ver2 = row2["Version"].strip("=~^")
                if version_satisfies(ver2, ver1) or version_satisfies(ver1, ver2):
                    rows.append({"Package": pkg_name, "Version": row2["Version"]})
        return pd.DataFrame(rows)
    else:
        common_packages = pd.merge(compromised_df[["Package"]], installed_df[["Package"]], on="Package", how="inner")
        return common_packages


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="URL to the compromised packages CSV")
    parser.add_argument("--lock-file", required=True, help="Path to package-lock.json")
    parser.add_argument("--check-version", default="true", help="Check both package and version if True, else only package name")
    args = parser.parse_args()

    df1 = load_compromised_packages_csv(args.url)
    df2 = load_package_lock_json(args.lock_file)
    common_df = find_common_packages(df1, df2, check_version=args.check_version)
    if common_df.empty:
        print("No vulnerable packages found in project.")
    else:
        print(f"\nFound vulnerable packages in project: {len(common_df)}")
        print(common_df.to_string(header=False, index=False))
        exit(1)
