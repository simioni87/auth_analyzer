# Auth Analyzer

## What is it?
The Burp extension helps you to find authorization bugs. Just navigate through the web application with a high privileged user and let the Auth Analyzer repeat your requests for any defined non-privileged user. CSRF Tokens of the non-privileged users will be extracted and replaced automatically and each response will be analyzed on its bypass status.

## How does it work?
1.	Create a “New Session” for each user role you want to test (e.g. admin, normal_user, unauthenticated, …) 
2.	Paste the session characteristic (e.g. Session Cookie, Authorization Header, …) for each role into the text area “Header(s) to replace”. Use the whole header for it (e.g. Cookie: session=123456;). Header(s) can be marked and send from anywhere to Auth Analyzer over the standard context menu (mark text and right click).
3.	If needed: Define CSRF Token Name for each role
    
    a. With a dynamic value (the CSRF token value will be automatically grepped if it is present in a HTML-input tag or JSON object of a given response)
    
    b. With a static value (value can be defined)
    
    c. Remove CSRF Token (to test CSRF check mechanism or for other purposes)
    
4.	If needed: Add your preferred “Grep and Replace” Rules (a start and stop string can be defined for Grep and Replace. Each grepped value will be replaced within the defined Replace rule of the given session).
5. Define Filters (only relevant requests should be processed)
6.	Start the “Auth Analyzer”. 
7.	Navigate with a high privileged user through the web application and access resources / functions which should not be accessible by your defined roles (sessions). All unfiltered proxy request will be modified, repeated and analyzed (for each role) by the Auth Analyzer. The results are displayed in the Auth Analyzer Tab.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/auth_analyzer_pic.png)


## Processing Filter
The “Auth Analyzer” should only process Requests which eighter containing a CSRF Token or implementing an access restriction. For this reason, following filters can be defined:
*	Only In Scope (only requests to the set Scope will be processed)
*	Only Proxy Traffic (only requests to the “Proxy History will be processed)
*	Exclude Filetypes (specified Filetypes can be excluded)
*	Exclude HTTP Methods (specified HTTP Methods can be excluded)
*	Exclude Status Codes (specified Status Codes can be excluded)
*	Exclude Paths (specified Paths can be excluded)
*	Exclude Queries / Params (specified Queries / Params can be excluded) 

## Bypass Detection
*	The Response will be declared as BYPASSED if “Both Responses have same Response Body”
*	The Response will be declared as POTENTIAL_BYPASSED if either “Both Responses have same Response Code” or “Both Responses have +-5% of response body length”
*	The Response will be declared as NOT_BYPASSED in every other case

## Features
*	Session Creation for each user role
*	Renaming and Removing a Session
*	Automatically grep and replace of CSRF token
*	Static replacement of a CSRF Token
*	Remove a specified parameter
*	Specify personal Grep and Replace Rules
*	Detailed Filter Rules
*	Number of filtered Requests for each Filter displayed in Session Info Panel
*	Detailed Status Panel for each Session
*	Start / Stop / Pause the “Auth Analyzer”
*	Detailed view of all processed Requests and Responses
*   Send marked text directly to "Header(s) to replace" text field by context menu item

## Implementation Details
| Topic | Type | Explanation |
| ------------ | ------------- | ------------- |
Header(s) to Replace | Specify several headers | Specify each header in a new line
Header(s) to Replace | No Header is specified | No header will be replaced
Header(s) to Replace | The specified Header not exists in request | The header will be added
Filter requests with exact same header(s) | How does it work? | The request will be filtered if all defined headers exist in request. The request will not be repeated for all specified sessions. Prevents repeating automatically generated requests (by JavaScript) from tested session
CSRF Token Parameter Name | Leave empty | No CSRF token manipulation will be applied
CSRF Token Parameter Name | Remove CSRF Token | With syntax remove_token#csrf_token, the defined CSRF Token Name will be replaced with "dummyparam" in header and / or body
CSRF Token Parameter Name | Replacement Location | The CSRF Token will be replaced / removed at following locations: GET Query Parameter, POST URL Encoded Body, POST Multipart Formdata Body, POST JSON Body
CSRF Token in Header | Static CSRF Token in Header | A static CSRF Token in header (e.g. X-XSRF-TOKEN) can be set in "Header(s) to Replace"
CSRF Token auto replacement | How does it work | The CSRF Token of each session will be extracted if the corresponding request is not filtered. CSRF tokens will be extracted at following places: Within HTML Document in an input element if the name attribute equals the specified "CSRF Token Parameter Name", Within a JSON Response if the root node contains a name equals the specified "CSRF Token Parameter Name"
Grep and Replace Rule | How does it work  | The specified value within the defined "Grep Rule" will be grepped for each session if the corresponding request is not filtered. The given value will be replaced for each session if the defined "Replace Rule" occurs in a given request
Request filter | How does it work | All requests matching a filter will not be repeated and action can occur for either Bypass detection or extracting a value (by "Auto CSRF token extraction" or "Grep Rule")
