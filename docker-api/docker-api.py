import os
import sys

from cvss_rescore.cvsslib import CvssLib
from cvss_rescore.manualVettingException import ManualVettingException

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from pydantic import BaseModel
from rule_engine import SymbolResolutionError, RuleSyntaxError

import logging

FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
FILENAME = f'{__name__}.log'
logging.basicConfig(format=FORMAT, filename=FILENAME)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(stream=sys.stdout)
logger.addHandler(ch)


class RescoreRequest(BaseModel):
    record: dict
    original_vector_string: str


class RescoreResponse(BaseModel):
    modified_vector_string: str
    modified_environmental_score: str
    modified_severity: str
    rules_applied: list


class ErrorResponse(BaseModel):
    message: str


app = FastAPI()

rules_file_path = os.path.join(os.getcwd(), 'rules_actions.json')


@app.exception_handler(ManualVettingException)
def manual_vetting_exception_handler(request: Request, exception: ManualVettingException):
    return JSONResponse(
        status_code=500,
        content={"message": "This vulnerability could not be rescored using cvss-rescore. "
                            "Either the cvss score is in an unsupported format, or no rules"
                            "were applied"}
    )


@app.exception_handler(SymbolResolutionError)
def symbol_resolution_exception_handler(request: Request, exception: SymbolResolutionError):
    return JSONResponse(
        status_code=500,
        content={"message": exception.message}
    )


@app.exception_handler(RuleSyntaxError)
def rule_syntax_exception_handler(request: Request, exception: RuleSyntaxError):
    return JSONResponse(
        status_code=500,
        content={"message": exception.message}
    )


@app.post("/rescore")
def rescore(rescore_request: RescoreRequest):
    cr = CvssLib(rules_file_path=rules_file_path)

    try:
        # return the 4-value tuple from the get_modified_cvss
        modified_vector_string, \
            modified_environmental_score, \
            modified_severity, rules_applied = \
            cr.get_modified_cvss(
                record=rescore_request.record,
                original_vector_string=rescore_request.original_vector_string)

        response = RescoreResponse(
            modified_vector_string=modified_vector_string,
            modified_environmental_score=modified_environmental_score,
            modified_severity=modified_severity[-1],
            rules_applied=rules_applied)

        return response

    except ManualVettingException:
        # No rules were applied to the vulnerability, or the vulnerability is using a version of CVSS older than 3.0
        raise manual_vetting_exception_handler()

    except SymbolResolutionError as sre:
        # There was an issue with the rule in the rules_actions.json file
        raise symbol_resolution_exception_handler(exception=sre)

    except RuleSyntaxError as rse:
        # There is an unrecognized vector metric, or incorrect value assigned to a cvss vector metric in the rule
        # file
        raise rule_syntax_exception_handler(exception=rse)
