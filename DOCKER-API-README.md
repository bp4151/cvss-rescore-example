# docker-api Example

## Explanation
If you are using a different language platform than Python and want to be able to 
rescore a single vulnerability at a time, you can Dockerize the process. This example assumes you are using
your favorite language to iterate through your vulnerabilities. When you want to rescore, you can just
post the original cvss score and vulnerability record to an api endpoint and get the modified results back
as a JSON object

## Running

The following example assumes you already have Docker Desktop running on your machine

1. If necessary, switch Docker Desktop to run Linux containers
2. Clone this project to your local machine
3. cd to the docker-api folder
4. Open Dockerfile, and set the desired internal port if you want an internal port other than 80. 
Port 80 will be fine if you map it to a different port in the docker-compose.yml file
5. Open docker-compose.yml 
6. Set the 9090 port to the desired port if you want to connect to a port other than 9090. 
This is the port you will use to connect to the API endpoint.
7. Map the volume as needed. By default, this docker-compose file is set to map the local folder 
that you are running from to the /app folder inside the container. This mapping is used so your 
rules_actions.json file can be read from the running container. If you place your rules_actions.json 
file elsewhere, set the `./` part of the volume map to your host file location.  
8. at the command prompt, enter `docker-compose up -d`
9. navigate to http://localhost:9090/docs (or other port as set above) to see the OpenAPI documentation
10. to stop your instance, enter `docker-compose down`

## Rescoring a Vulnerability

1. Open the results.json file in the root directory
2. Copy any single vulnerability object from the array of vulnerabilities
3. Navigate to http://localhost:9090/docs (or other port as set above)
4. Expand the rescore endpoint
5. Click the Try it Out button
6. Enter a new dictionary containing a "record" attribute and "original_vector_string" attribute.
e.g.
```
{
  "record":     {
      "id": "SNYK-PYTHON-CERTIFI-3164749",
      "title": "Insufficient Verification of Data Authenticity",
      "CVSSv3": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N",
      "credit": [
        "Joel Reardon"
      ],
      "semver": {
        "vulnerable": [
          "[,2022.12.7)"
        ]
      },
      "exploit": "Not Defined",
      "fixedIn": [
        "2022.12.7"
      ],
      "patches": [],
      "insights": {
        "triageAdvice": null
      },
      "language": "python",
      "severity": "medium",
      "cvssScore": 6.8,
      "functions": [],
      "malicious": false,
      "moduleName": "certifi",
      "references": [
        {
          "url": "https://github.com/certifi/python-certifi/commit/9e9e840925d7b8e76c76fdac1fab7e6e88c1c3b8",
          "title": "GitHub Commit"
        },
        {
          "url": "https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/oxX69KFvsm4/m/yLohoVqtCgAJ",
          "title": "Google Groups Forum"
        }
      ],
      "cvssDetails": [
        {
          "assigner": "SUSE",
          "severity": "medium",
          "cvssV3Vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
          "cvssV3BaseScore": 6.6,
          "modificationTime": "2023-01-21T11:01:34.289666Z"
        },
        {
          "assigner": "NVD",
          "severity": "high",
          "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
          "cvssV3BaseScore": 7.5,
          "modificationTime": "2022-12-14T01:12:06.023186Z"
        }
      ],
      "description": "## Overview\n\nAffected versions of this package are vulnerable to Insufficient Verification of Data Authenticity resulting in Certifi root certificate removal from TrustCor. The root certificates are being removed pursuant to an investigation prompted by media reporting that TrustCor's ownership also operated a business that produced spyware.\n## Remediation\nUpgrade `certifi` to version 2022.12.7 or higher.\n## References\n- [GitHub Commit](https://github.com/certifi/python-certifi/commit/9e9e840925d7b8e76c76fdac1fab7e6e88c1c3b8)\n- [Google Groups Forum](https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/oxX69KFvsm4/m/yLohoVqtCgAJ)\n",
      "identifiers": {
        "CVE": [
          "CVE-2022-23491"
        ],
        "CWE": [
          "CWE-345"
        ],
        "GHSA": [
          "GHSA-43fp-rhv2-5gv8"
        ]
      },
      "packageName": "certifi",
      "proprietary": false,
      "creationTime": "2022-12-08T09:22:24.241183Z",
      "functions_new": [],
      "alternativeIds": [],
      "disclosureTime": "2022-12-07T23:05:18Z",
      "packageManager": "pip",
      "publicationTime": "2022-12-08T09:37:59.689622Z",
      "modificationTime": "2023-01-21T11:01:34.289666Z",
      "socialTrendAlert": false,
      "severityWithCritical": "medium",
      "from": [
        "bruberbettorbot@0.0.0",
        "requests@2.27.1",
        "certifi@2021.10.8"
      ],
      "upgradePath": [],
      "isUpgradable": false,
      "isPatchable": false,
      "name": "certifi",
      "version": "2021.10.8"
    },
  "original_vector_string": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N"
}
```
7. Press the "Execute" button

