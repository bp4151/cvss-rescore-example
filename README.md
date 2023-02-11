# cvss-rescore-example
Example project for using the cvss-rescore library

## Source File

The source file results.json is a Snyk SCA scan output file that contains the analysis of my BettorBot project. 

## About the BettorBot project

Knowing the code and configuration of my BettorBot application allows me to configure my environmental vector metrics 
so I can more accurately score my vulnerabilities. 

My BettorBot project simply retrieves data from two different APIs, compares the data, and generates bet 
suggestions based on custom business logic. There is no sensitive data, so we can  
1. set the environmental confidentiality vector metric to Low or even None. 
2. set the environmental integrity vector metric to Low or even None. 
3. set the environmental Modified Attack Vector vector metric to High since I run the BettorBot inside of a Docker container, and it is run
within my CI/CD pipeline. A malicious actor would need to bypass my MFA and login to perform an attack. 

## Understanding the Sample Project
1. Results of the BettorBot project Snyk SCA scan are in the results.json file
2. The custom rules are contained in the rules_actions.json file.
3. The main.py file contains basic processing for the purposes of the example. While we don't currently use Snyk at Paylocity, the main.py business 
logic is similar in functionality to how we use the cvss-rescore package in our projects

## Running the Sample Project

Pipenv instructions: https://docs.python-guide.org/dev/virtualenvs/

This project uses a Pipfile and pipenv 
To run this project, simply clone the project to your local machine, change directories to your cloned location, 
and run
```
pipenv shell
pipenv install
python main.py
```

## Sample Output

```
2023-02-11 11:19:05,727 - __main__ - INFO - 
+------------------------+--------------------------------------------------------------+
| field                  | value                                                        |
+------------------------+--------------------------------------------------------------+
| package_name           | certifi                                                      |
| package_version        | 2021.10.8                                                    |
| original_vector_string | CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N                 |
| original_score         | 6.8                                                          |
| original_severity      | medium                                                       |
| rescored_vector_string | CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N/MAV:N/MAC:H/MPR |
|                        | :H/MUI:N/MC:N/MI:N/MA:N/RL:O/RC:C                            |
| rescored_score         | 0.0                                                          |
| rescored_severity      | None                                                         |
| rules_applied          | [{'description': 'Fix version exists, set RL=O',             |
|                        | 'vector_changes': [{'vector': 'RL', 'value': 'O'}]},         |
|                        | {'description': 'CVE exists, set RC=C', 'vector_changes':    |
|                        | [{'vector': 'RC', 'value': 'C'}]}, {'description': 'Certifi  |
|                        | TrustCor Vulnerability', 'vector_changes': [{'vector':       |
|                        | 'MAC', 'value': 'H'}, {'vector': 'MC', 'value': 'N'},        |
|                        | {'vector': 'MI', 'value': 'N'}, {'vector': 'MA', 'value':    |
|                        | 'N'}]}]                                                      |
+------------------------+--------------------------------------------------------------+
2023-02-11 11:19:05,732 - __main__ - INFO - 
+------------------------+--------------------------------------------------------------+
| field                  | value                                                        |
+------------------------+--------------------------------------------------------------+
| package_name           | certifi                                                      |
| package_version        | 2021.10.8                                                    |
| original_vector_string | CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N                 |
| original_score         | 6.8                                                          |
| original_severity      | medium                                                       |
| rescored_vector_string | CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N/MAV:N/MAC:H/MPR |
|                        | :H/MUI:N/MC:N/MI:N/MA:N/RL:O/RC:C                            |
| rescored_score         | 0.0                                                          |
| rescored_severity      | None                                                         |
| rules_applied          | [{'description': 'Fix version exists, set RL=O',             |
|                        | 'vector_changes': [{'vector': 'RL', 'value': 'O'}]},         |
|                        | {'description': 'CVE exists, set RC=C', 'vector_changes':    |
|                        | [{'vector': 'RC', 'value': 'C'}]}, {'description': 'Certifi  |
|                        | TrustCor Vulnerability', 'vector_changes': [{'vector':       |
|                        | 'MAC', 'value': 'H'}, {'vector': 'MC', 'value': 'N'},        |
|                        | {'vector': 'MI', 'value': 'N'}, {'vector': 'MA', 'value':    |
|                        | 'N'}]}]                                                      |
+------------------------+--------------------------------------------------------------+
2023-02-11 11:19:05,737 - __main__ - INFO - 
+------------------------+--------------------------------------------------------------+
| field                  | value                                                        |
+------------------------+--------------------------------------------------------------+
| package_name           | setuptools                                                   |
| package_version        | 57.0.0                                                       |
| original_vector_string | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H                 |
| original_score         | 5.9                                                          |
| original_severity      | medium                                                       |
| rescored_vector_string | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H/MAV:N/MAC:H/MPR |
|                        | :N/MUI:N/MC:N/MI:N/MA:N/RL:O/RC:C                            |
| rescored_score         | 0.0                                                          |
| rescored_severity      | None                                                         |
| rules_applied          | [{'description': 'Fix version exists, set RL=O',             |
|                        | 'vector_changes': [{'vector': 'RL', 'value': 'O'}]},         |
|                        | {'description': 'CVE exists, set RC=C', 'vector_changes':    |
|                        | [{'vector': 'RC', 'value': 'C'}]}, {'description':           |
|                        | 'setuptools transitive ReDos', 'vector_changes': [{'vector': |
|                        | 'MAC', 'value': 'H'}, {'vector': 'MC', 'value': 'N'},        |
|                        | {'vector': 'MI', 'value': 'N'}, {'vector': 'MA', 'value':    |
|                        | 'N'}]}]                                                      |
+------------------------+--------------------------------------------------------------+
```
