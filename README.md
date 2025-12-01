# Vulnerable Package Scanner

A Python utility to detect vulnerable or compromised npm packages by shai hulud by comparing project's **package-lock.json** against a known list of compromised package versions from a CSV file.

## Overview

This script loads:
1. A CSV file containing known compromised npm packages\
2. A package-lock.json from your project

It then checks for: - Matching package names\
- (Optional) Matching package versions

Finally, it prints a list of vulnerable packages if any are found.

## Features

-   Parses `package-lock.json` and extracts all installed packages.
-   Supports vulnerable CSV entries with multiple versions separated by
    `||`.
-   Matches packages **by name** or **by name + exact version**.
-   Uses `packaging.version` for precise version comparison.
-   Flags the build (`exit 1`) if vulnerable packages are detected.

## Input Format

### 1. Compromised Packages CSV

  Package       Version
  ------------- ------------------
  package-one   1.0.0
  package-two   2.5.1

### 2. package-lock.json

A standard npm `package-lock.json` file.

## Usage

``` bash
python3 scanner.py --url https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/shai-hulud-2-packages.csv --lock-file ./package-lock.json --check-version true
```

### Arguments

  -----------------------------------------------------------------------
  Argument              Required              Description
  --------------------- --------------------- ---------------------------
  `--url`               Yes                   URL or path to compromised
                                              packages CSV

  `--lock-file`         Yes                   Path to your
                                              `package-lock.json`

  `--check-version`     No                    If `true`, checks package +
                                              version. If `false`, checks
                                              only package names.
                                              Default: `true`
  -----------------------------------------------------------------------

## Example Output

    Found vulnerable packages in project: 3
    lodash 4.17.21
    minimist 1.2.5
    axios 0.21.1

## Exit Codes

  Exit Code   Meaning
  ----------- ------------------------------
  `0`         No vulnerable packages found
  `1`         Vulnerable packages detected

## Dependencies

``` bash
pip install pandas
```
