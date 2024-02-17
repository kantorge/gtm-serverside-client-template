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


const cookieWhiteList = ['xnpe_' + data.projectToken, '__exponea_etc__', '__exponea_time2__'];
const headerWhiteList = ['referer', 'user-agent', 'etag'];

const containerVersion = getContainerVersion();
const isDebug = containerVersion.debugMode;
const isLoggingEnabled = determinateIsLoggingEnabled();
const traceId = getRequestHeader('trace-id');

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

    logToConsoleIfEnabled(
        'Response',
        'Response to forwarded request recieved',
        {
            'ResponseStatusCode': result.statusCode,
            'ResponseHeaders': result.headers,
            'ResponseBody': result.body,
        }
    );

    for (const key in result.headers) {
        if (key === 'set-cookie') {
            setResponseCookies(result.headers[key]);
        } else {
            setResponseHeader(key, result.headers[key]);
        }
    }

    setResponseBody(result.body);
    setResponseStatus(result.statusCode);

    // Set the CORS headers
    if (requestOrigin) {
        setResponseHeader('access-control-allow-origin', requestOrigin);
        setResponseHeader('access-control-allow-credentials', 'true');
    }

    returnResponse();

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