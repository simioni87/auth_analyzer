# Auth Analyzer

## What is it?
The Burp extension helps you to find authorization bugs. Just navigate through the web application with a high privileged user and let the Auth Analyzer repeat your requests for any defined non-privileged user. With the possibility to define Parameters the Auth Analyzer is able to extract and replace parameter values automatically. With this for instance, CSRF tokens or even whole session characteristics can be auto extracted from responses and replaced in further requests. Each response will be analyzed and tagged on its bypass status. 

## How does it work
(1) Create or Clone a Session for every user you want to test.

(2) Specify the session characteristics (Header(s) and / or Parameter(s) to replace)

(3) Optional: Set Filters

(4) Press Start

(5) Navigate through Web App with another user and track results of the repeated requests

(6) Manually analyze original and repeated requests / responses 


![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/complete_gui.png)


## Sample Usage

### Session Header and CSRF Token Parameter
Define a Cookie header and a csrf token (with auto value extract). The csrf token value will be extracted if it is located in a repeated response of the given session.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/session_header_with_csrf_token.png)

### Auto extract session Cookie
Define the username and password as a static value. The session cookie name must be defined as auto extract. Verify that you start navigating through the application with no session cookie. Login to the web app; the auth analyzer will repeat the login request with your parameters and automatically gets the session of the defined user.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/auto_extract_session_id.png)

### Auto extract from JavaScript variable
Since the Auto Extract only works on "HTML Input Fields", "JSON Objects" or "Set-Cookie Headers" we must use the generic extraction method called "From To String". With this extraction method we can extract any value from a response if it is located after a unique starting and / or ending string. Auth Analyzer provides a context menu method to set the "From String" and "To String" automatically. Just mark the String you want to extract and set as "From-To Extract".

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/auto_extract_csrftoken_from_js_var.png)

### Auto extract and insert as Bearer Token
Since the Authorization Header is not treated as a parameter (as it is done with the Cookie Header), we must use and insertion point to insert the automatically extracted value of the Bearer Token. Just mark and right click the value you want to replace in the specified header. The default value will be used if the parameter value is not extracted yet.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/autp_extract_and_insert_bearer_token.png)

### Test several privilege roles at a time
Just create as many sessions as you want to test several roles at a time. 

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/several_sessions.png)

## Processing Filter
The Auth Analyzer should process two types of requests / responses:
•	The response contains a value which must be extracted
•	The requested resource should not be accessible by the defined session(s)
For instance, we don’t want to process a static JavaScript file because it is accessible for everyone and (hopefully) does not contain any protected data. To achieve this, we can set following types of filters:
*	Only In Scope (only requests to the set Scope will be processed)
*	Only Proxy Traffic (only requests to the "Proxy History" will be processed)
*	Exclude Filetypes (specified Filetypes can be excluded)
*	Exclude HTTP Methods (specified HTTP Methods can be excluded)
*	Exclude Status Codes (specified Status Codes can be excluded)
*	Exclude Paths (specified Paths can be excluded)
*	Exclude Queries / Params (specified Queries / Params can be excluded) 

## Bypass Detection
*	The Response will be declared as BYPASSED if "Both Responses have same Response Body" and "same Response Code"
*	The Response will be declared as POTENTIAL_BYPASSED if "Both Responses have same Response Code" and "Both Responses have +-5% of response body length"
*	The Response will be declared as NOT_BYPASSED in every other case

## Features
*	Session Creation for each user role
*	Renaming and Removing a Session
*   Clone a Session
*	Set any amount of replacing parameters
*	Define how the parameter value will be discovered (automatic, static, prompt for input)
*	Remove a specified parameter
*	Detailed Filter Rules
*	Detailed Status Panel for each Session
*	Start / Stop / Pause the "Auth Analyzer"
*	Detailed view of all processed Requests and Responses
*	Send Header(s) and / or Parameter(s) directly to Auth Analyzer by Context Menu
*   Auto save current configuration 
