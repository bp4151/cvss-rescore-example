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
