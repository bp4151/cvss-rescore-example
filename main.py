import json
import logging
import os
from pprint import pprint as pp

from cvss_rescore.manualVettingException import ManualVettingException
from prettytable import PrettyTable

from cvss_rescore.cvsslib import CvssLib, SymbolResolutionError, RuleSyntaxError

# we need a logger to pass into the cvss-rescore package, so we'll create one here
FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
FILENAME = f'{__name__}.log'
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter(FORMAT)
ch = logging.StreamHandler()
ch.setFormatter(formatter)
ch.setLevel(logging.DEBUG)
fh = logging.FileHandler(FILENAME)
fh.setFormatter(formatter)
fh.setLevel(logging.DEBUG)

logger.addHandler(ch)
logger.addHandler(fh)


def main():
    # we will need the full path to our custom rules file
    rules_file_path = os.path.join(os.getcwd(), 'rules_actions.json')

    # we need our results file
    results_file_path = os.path.join(os.getcwd(), 'results.json')
    # open the results file and load the json
    with open(file=results_file_path, encoding="utf8") as input:
        results = json.load(input)

    # loop through the vulnerabilities
    for vulnerability in results.get('vulnerabilities'):

        table = PrettyTable(['field', 'value'])
        table.align = 'l'
        table._max_width = {'field': 60, 'value': 60}

        # we will need the original cvss vector string
        original_cvss_string = vulnerability.get('CVSSv3')
        original_cvss_score = vulnerability.get('cvssScore')
        original_severity = vulnerability.get('severity')

        # let's create a CvssLib object
        cr = CvssLib(rules_file_path=rules_file_path)

        try:
            # return the 4-value tuple from the get_modified_cvss
            modified_vector_string, \
                modified_environmental_score, \
                modified_severity, rules_applied = \
                cr.get_modified_cvss(record=vulnerability, original_vector_string=original_cvss_string)

            # everything below is just output
            fields = {
                'package_name': vulnerability.get('packageName'),
                'package_version': vulnerability.get('version'),
                'original_vector_string': original_cvss_string,
                'original_score': original_cvss_score,
                'original_severity': original_severity,
                'rescored_vector_string': modified_vector_string,
                'rescored_score': modified_environmental_score,
                'rescored_severity': modified_severity[-1],
                'rules_applied': rules_applied
            }

            for key, val in fields.items():
                table.add_row([key, val])

            logger.info(f'\n{table}')
        except ManualVettingException as mve:
            # No rules were applied to the vulnerability, or the vulnerability is using a version of CVSS older than 3.0
            logger.error(mve)
        except SymbolResolutionError as sre:
            # There was an issue with the rule in the rules_actions.json file
            logger.error(sre.message)
        except RuleSyntaxError as rse:
            # There is an unrecognized vector metric, or incorrect value assigned to a cvss vector metric in the rule
            # file
            logger.error(rse.message)


if __name__ == '__main__':
    main()
