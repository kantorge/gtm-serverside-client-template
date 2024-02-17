___INFO___

{
  "type": "CLIENT",
  "id": "cvt_temp_public_id",
  "version": 1,
  "securityGroups": [],
  "displayName": "Exponea Analytics Client",
  "brand": {
    "id": "brand_dummy",
    "displayName": "",
    "thumbnail": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAOEAAADhCAMAAAAJbSJIAAAAM1BMVEX/zQAcFzP/0gAAADSohyH/1gClhCL/zwAAADehgSPWrBWwjSD/2wAPDTSsiiD/3wBxWyvoA5xkAAABPUlEQVR4nO3cW26DMBRF0WAgDSWPzn+0/bdV0JUq2TdZawTeUfIBB3K5AAAAAAAAAAAAAAAAAAAAwLjWqNL7xEHrbY65bckS13mKmReFg1GocHwKFY5PocLxKVQ4vqbwcXb5dE1e+Ph5Loeu31+9zxxTF87PtRxLFtgWZvuZnVKYn8L8FOanMD+F+SnM7/0KS7V3vurC/Z57IS1bvYhOlewLaVmi92WaT2Dwr7FChQr7U6hQYX8KFSrs7xMLg4+XDr+QNoXzfjyIpltI28L7ySCabSFtC9feR/pnCvNTmJ/C/BTmpzA/hfm9YWE1b973uvCV/B3S9hXRqRK9xB9tIQ0/qH5qtPs0ChUq7E+hQoX9KVSosL8PKIz+wc65wRbSsgUH0HwLaXT/TL+QAgAAAAAAAAAAAAAAAAAA/O0Xm1MdrfEGnRgAAAAASUVORK5CYII\u003d"
  },
  "description": "Exponea helps you maximize profits and drive customer loyalty by targeting the right customers with the right message at the perfect time.",
  "containerContexts": [
    "SERVER"
  ]
}


___TEMPLATE_PARAMETERS___

[
  {
    "type": "TEXT",
    "name": "projectToken",
    "displayName": "Project token",
    "simpleValueType": true,
    "valueValidators": [
      {
        "type": "NON_EMPTY"
      }
    ],
    "help": "Please provide your Exponea project token. It is used to correctly handle Exponea cookies in forwarded requests."
  },
  {
    "type": "TEXT",
    "name": "targetAPI",
    "displayName": "API endpoint",
    "simpleValueType": true,
    "valueValidators": [
      {
        "type": "NON_EMPTY"
      }
    ],
    "help": "The root URL, where Exponea requests need to be forwarded.",
    "valueHint": "e.g https://exponea.example.com"
  },
  {
    "type": "SIMPLE_TABLE",
    "name": "proxyStaticPathList",
    "displayName": "List of files, which are served statically. `/js/exponea.min.js` is handled by default, and it doesn\u0027t have to be repeated.",
    "simpleTableColumns": [
      {
        "defaultValue": "",
        "displayName": "File path",
        "name": "filePath",
        "type": "TEXT",
        "valueHint": "/path/to/file.js",
        "isUnique": true,
        "valueValidators": []
      }
    ]
  },
  {
    "type": "GROUP",
    "name": "logsGroup",
    "displayName": "Logs Settings",
    "groupStyle": "ZIPPY_CLOSED",
    "subParams": [
      {
        "type": "RADIO",
        "name": "logType",
        "radioItems": [
          {
            "value": "no",
            "displayValue": "Do not log"
          },
          {
            "value": "debug",
            "displayValue": "Log to console during debug and preview"
          },
          {
            "value": "always",
            "displayValue": "Always log to console"
          }
        ],
        "simpleValueType": true,
        "defaultValue": "debug"
      }
    ]
  }
]


___SANDBOXED_JS_FOR_SERVER___

// Import required modules
const claimRequest = require('claimRequest');
const getCookieValues = require('getCookieValues');
const getRequestBody = require('getRequestBody');
const getRequestHeader = require('getRequestHeader');
const getRequestMethod = require('getRequestMethod');
const getRequestPath = require('getRequestPath');
const getRequestQueryString = require('getRequestQueryString');
const JSON = require('JSON');
const logToConsole = require('logToConsole');
const returnResponse = require('returnResponse');
const setCookie = require('setCookie');
const templateDataStorage = require('templateDataStorage');
const sendHttpGet = require('sendHttpGet');
const getTimestampMillis = require('getTimestampMillis');
const sendHttpRequest = require('sendHttpRequest');
const setResponseBody = require('setResponseBody');
const setResponseHeader = require('setResponseHeader');
const setResponseStatus = require('setResponseStatus');
const getContainerVersion = require('getContainerVersion');
const getRemoteAddress = require('getRemoteAddress');

// Prepare optionally enabled logging
const containerVersion = getContainerVersion();
const isDebug = containerVersion.debugMode;
const isLoggingEnabled = determinateIsLoggingEnabled();

// Let's get processing the requested path
const traceId = getRequestHeader('trace-id');
const path = getRequestPath();
logToConsoleIfEnabled('Message', 'Starting Exponea client script to serve ' + path);

// Define the default path, which is served statically from the proxy
const staticPathList = [
    '/js/exponea.min.js',
];

// Get the user defined static path list and merge it with the default one, accounting for duplicates
const customStaticPathList = data.proxyStaticPathList || [];
customStaticPathList.forEach((item) => {
    const path = item.filePath.trim();
    if (staticPathList.indexOf(path) > -1) {
        staticPathList.push(path);
    }
});

// Check if this Client should serve any static files
if (staticPathList.indexOf(path) > -1) {
    logToConsoleIfEnabled('Message', 'Claiming request');
    claimRequest();

    const now = getTimestampMillis();
    const thirty_minutes_ago = now - (30 * 60 * 1000);

    if (templateDataStorage.getItemCopy(path) == null || templateDataStorage.getItemCopy(path + '_stored_at') < thirty_minutes_ago) {
        const completeURL = data.targetAPI + path;
        logToConsoleIfEnabled(
            'Response',
            'Serving and caching static file',
            {
                'Path': path,
                'URL': completeURL,
            }
        );

        sendHttpGet(
            completeURL,
            {
                headers: {'X-Forwarded-For': getRemoteAddress()}
            }
        ).then((result) => {
            if (result.statusCode === 200) {
                templateDataStorage.setItemCopy(path, result.body);
                templateDataStorage.setItemCopy('exponea_headers', result.headers);
                templateDataStorage.setItemCopy(path + '_stored_at', now);
            }
            sendProxyResponse(result.body, result.headers, result.statusCode);
        });
    } else {
        logToConsoleIfEnabled(
            'Response',
            'Serving static file from cache',
            {
                'Path': path,
            }
        );

        sendProxyResponse(
            templateDataStorage.getItemCopy(path),
            templateDataStorage.getItemCopy('exponea_headers'),
            200
        );
    }

    return;
}

// Check if this Client should serve exponea.js.map file (Just only to avoid annoying error in console)
if (path === '/js/exponea.min.js.map') {
    logToConsoleIfEnabled('Response', 'Absorping exponea.min.js.map request');
    sendProxyResponse('{"version": 1, "mappings": "", "sources": [], "names": [], "file": ""}', {'Content-Type': 'application/json'}, 200);

    return;
}

// Check if this Client should claim the request.
// The values are provided as the beginning of the supported paths
var managedPathList = [
    '/bulk',
    '/managed-tags/show',
    '/campaigns/banners/show',
    '/campaigns/experiments/show',
    '/campaigns/html/get',
    '/optimization/recommend/user',
    '/webxp/projects/',
    '/webxp/data/modifications/',
    '/webxp/bandits/reward',
    '/webxp/script-async/',
    '/webxp/script/',
];

// When there is no match, we should abort the request, as there are no further actions to be taken
if (!managedPathList.some(pattern => startsWith(path,pattern))) {
    logToConsoleIfEnabled('Message', 'Aborting, irrelevant request path: ' + path);

    return;
}

/**
 * This is one of the main functionalities, where we pass the request to the Exponea API, and then forward the response to the client
 */

logToConsoleIfEnabled('Message', 'Path is in the list of managed paths, claiming request');
claimRequest();

// Define the white list of cookies and headers to be passed to Exponea
const cookieWhiteList = ['xnpe_' + data.projectToken, '__exponea_etc__', '__exponea_time2__'];
const headerWhiteList = ['referer', 'user-agent', 'etag'];

// Grab the details of the request, and forward it to Exponea based on the configured endpoint
const requestOrigin = getRequestHeader('Origin');
const requestMethod = getRequestMethod();
const requestBody = getRequestBody();
const requestUrl = generateRequestUrl();
const requestHeaders = generateRequestHeaders();

logToConsoleIfEnabled(
    'Request',
    'Forwarding http request to Exponea',
    {
        'RequestOrigin': requestOrigin,
        'RequestMethod': requestMethod,
        'RequestUrl': requestUrl,
        'RequestHeaders': requestHeaders,
        'RequestBody': requestBody,
    }
);

sendHttpRequest(
    requestUrl,
    {
        method: requestMethod,
        headers: requestHeaders
    },
    requestBody
)
.then((result) => {
    logToConsoleIfEnabled(
        'Response',
        'Response to forwarded request recieved',
        {
            'ResponseStatusCode': result.statusCode,
            'ResponseHeaders': result.headers,
            'ResponseBody': result.body,
        }
    );

    // Pass the response headers to the client, with a few exceptions
    for (const key in result.headers) {
        // Skip the 'set-cookie' header, as it is processed separately by creating the response cookies
        if (key === 'set-cookie') {
            setResponseCookies(result.headers[key]);
            continue;
        }

        // CORS headers are skipped and set separately
        if (key.toLowerCase() === 'access-control-allow-origin') continue;
        if (key.toLowerCase() === 'access-control-allow-credentials') continue;

        // Temporarily disable the transfer-encoding header, as it is not supported by the proxy
        if (key.toLowerCase() === 'transfer-encoding') continue;

        // Pass all other headers to the client
        setResponseHeader(key, result.headers[key]);
    }

    // Set response body and status code
    setResponseBody(result.body || '');
    setResponseStatus(result.statusCode);

    // Set the CORS headers
    if (requestOrigin) {
        setResponseHeader('access-control-allow-origin', requestOrigin);
        setResponseHeader('access-control-allow-credentials', 'true');
    }

    // Set a custom header to indicate that the response was processed by SGTM
    setResponseHeader('X-Processed-By-SGTM', 'true');

    returnResponse();

    logToConsoleIfEnabled(
        'Response',
        'Exponea response sent to client',
        {
            statusCode: result.statusCode,
            headers: result.headers,
        }
    );
});

/**
 * This is the end of the main functionality, where we pass the request to the Exponea API, and then forward the response to the client
 * The rest of the file contains helper functions
 */

/**
 * Helper function to generate the request URL based on the target API and the requested path
 *
 * @returns {string} The generated request URL
 */
function generateRequestUrl() {
    let url = data.targetAPI + getRequestPath();
    const queryParams = getRequestQueryString();

    if (queryParams) url = url + '?' + queryParams;

    return url;
}

/**
 * Generates the request headers based on the predefined white list of headers and cookies.
 *
 * @returns {Object} The generated request headers.
 */
function generateRequestHeaders() {
    let headers = {};
    let cookies = [];

    for (let i = 0; i < headerWhiteList.length; i++) {
        let headerName = headerWhiteList[i];
        let headerValue = getRequestHeader(headerName);

        if (headerValue) {
            headers[headerName] = getRequestHeader(headerName);
        }
    }

    headers.cookie = '';

    for (let i = 0; i < cookieWhiteList.length; i++) {
        let cookieName = cookieWhiteList[i];
        let cookieValue = getCookieValues(cookieName);

        if (cookieValue && cookieValue.length) {
            cookies.push(cookieName + '=' + cookieValue[0]);
        }
    }

    headers.cookie = cookies.join('; ');
    headers['X-Forwarded-For'] = getRemoteAddress();

    return headers;
}

/**
 * Sets response cookies based on the provided setCookieHeader.
 *
 * @param {string[]} setCookieHeader - The array of cookies to be set in the response headers
 */
function setResponseCookies(setCookieHeader) {
    for (let i = 0; i < setCookieHeader.length; i++) {
        let setCookieArray = setCookieHeader[i].split('; ').map(pair => pair.split('='));
        let setCookieJson = '';

        for (let j = 1; j < setCookieArray.length; j++) {
            if (j === 1) setCookieJson += '{';
            if (setCookieArray[j].length > 1) setCookieJson += '"' + setCookieArray[j][0] + '": "' + setCookieArray[j][1] + '"'; else setCookieJson += '"' + setCookieArray[j][0] + '": ' + true;
            if (j + 1 < setCookieArray.length) setCookieJson += ','; else setCookieJson += '}';
        }

        setCookie(setCookieArray[0][0], setCookieArray[0][1], JSON.parse(setCookieJson));
    }
}

/**
 * Sends a proxy response with the specified response, headers, and status code.
 * This is a helper function to simplify the process of sending a response for simple requests.
 *
 * @param {any} response - The response to send.
 * @param {Object} headers - The headers to include in the response.
 * @param {number} statusCode - The status code of the response.
 * @returns {void}
 */
function sendProxyResponse(response, headers, statusCode) {
    setResponseStatus(statusCode);
    setResponseBody(response);

    for (const key in headers) {
        setResponseHeader(key, headers[key]);
    }

    returnResponse();
}

/**
 * Determines if logging is enabled based on the logType value, which is provided by the user.
 *
 * @returns {boolean} True if logging is enabled, false otherwise.
 */
function determinateIsLoggingEnabled() {
    // As a default behavior, if no setting is available for any reason, log during debug mode only
    if (!data.logType) {
        return isDebug;
    }

    if (data.logType === 'no') {
        return false;
    }

    if (data.logType === 'debug') {
        return isDebug;
    }

    return data.logType === 'always';
}

/**
 * Logs the message to the console if logging is enabled.
 *
 * @param {string} type - The type of the log message. Expected values are: Request, Response, Message.
 * @param {string} message - The message to be logged.
 * @param {Object} data - The data to be logged.
 * @returns {void}
 */
function logToConsoleIfEnabled(type, message, data) {
    if (!isLoggingEnabled) {
        return;
    }

    logToConsole(JSON.stringify({
        Name: 'Exponea Analytics Client',
        Type: type,
        TraceId: traceId,
        Message: message,
        Data: data
    }));
}

/**
 * Helper function to determine if an input string starts with an other given string
 *
 * @param {string} input
 * @param {string} pattern
 * @returns {boolean}
 */
function startsWith(input, pattern) {
    return input.indexOf(pattern) === 0;
}


___SERVER_PERMISSIONS___

[
  {
    "instance": {
      "key": {
        "publicId": "read_request",
        "versionId": "1"
      },
      "param": [
        {
          "key": "requestAccess",
          "value": {
            "type": 1,
            "string": "any"
          }
        },
        {
          "key": "headerAccess",
          "value": {
            "type": 1,
            "string": "any"
          }
        },
        {
          "key": "queryParameterAccess",
          "value": {
            "type": 1,
            "string": "any"
          }
        }
      ]
    },
    "clientAnnotations": {
      "isEditedByUser": true
    },
    "isRequired": true
  },
  {
    "instance": {
      "key": {
        "publicId": "return_response",
        "versionId": "1"
      },
      "param": []
    },
    "isRequired": true
  },
  {
    "instance": {
      "key": {
        "publicId": "access_response",
        "versionId": "1"
      },
      "param": [
        {
          "key": "writeResponseAccess",
          "value": {
            "type": 1,
            "string": "any"
          }
        },
        {
          "key": "writeHeaderAccess",
          "value": {
            "type": 1,
            "string": "specific"
          }
        }
      ]
    },
    "clientAnnotations": {
      "isEditedByUser": true
    },
    "isRequired": true
  },
  {
    "instance": {
      "key": {
        "publicId": "send_http",
        "versionId": "1"
      },
      "param": [
        {
          "key": "allowedUrls",
          "value": {
            "type": 1,
            "string": "any"
          }
        }
      ]
    },
    "clientAnnotations": {
      "isEditedByUser": true
    },
    "isRequired": true
  },
  {
    "instance": {
      "key": {
        "publicId": "set_cookies",
        "versionId": "1"
      },
      "param": [
        {
          "key": "allowedCookies",
          "value": {
            "type": 2,
            "listItem": [
              {
                "type": 3,
                "mapKey": [
                  {
                    "type": 1,
                    "string": "name"
                  },
                  {
                    "type": 1,
                    "string": "domain"
                  },
                  {
                    "type": 1,
                    "string": "path"
                  },
                  {
                    "type": 1,
                    "string": "secure"
                  },
                  {
                    "type": 1,
                    "string": "session"
                  }
                ],
                "mapValue": [
                  {
                    "type": 1,
                    "string": "*"
                  },
                  {
                    "type": 1,
                    "string": "*"
                  },
                  {
                    "type": 1,
                    "string": "*"
                  },
                  {
                    "type": 1,
                    "string": "any"
                  },
                  {
                    "type": 1,
                    "string": "any"
                  }
                ]
              }
            ]
          }
        }
      ]
    },
    "clientAnnotations": {
      "isEditedByUser": true
    },
    "isRequired": true
  },
  {
    "instance": {
      "key": {
        "publicId": "get_cookies",
        "versionId": "1"
      },
      "param": [
        {
          "key": "cookieAccess",
          "value": {
            "type": 1,
            "string": "any"
          }
        }
      ]
    },
    "clientAnnotations": {
      "isEditedByUser": true
    },
    "isRequired": true
  },
  {
    "instance": {
      "key": {
        "publicId": "read_container_data",
        "versionId": "1"
      },
      "param": []
    },
    "isRequired": true
  },
  {
    "instance": {
      "key": {
        "publicId": "access_template_storage",
        "versionId": "1"
      },
      "param": []
    },
    "isRequired": true
  },
  {
    "instance": {
      "key": {
        "publicId": "logging",
        "versionId": "1"
      },
      "param": [
        {
          "key": "environments",
          "value": {
            "type": 1,
            "string": "debug"
          }
        }
      ]
    },
    "clientAnnotations": {
      "isEditedByUser": true
    },
    "isRequired": true
  }
]


___TESTS___

scenarios: []


___NOTES___

Created on 24. 8. 2021, 13:27:38
