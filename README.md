# Auth Analyzer

## What is it?
The Burp extension helps you to find authorization bugs. Just navigate through the web application with a high privileged user and let the Auth Analyzer repeat your requests for any defined non-privileged user. With the possibility to define Parameters the Auth Analyzer is able to extract and replace parameter values automatically. With this for instance, CSRF tokens or even whole session characteristics can be auto extracted from responses and replaced in further requests. Each response will be analyzed and tagged on its bypass status. 

## How does it work?
(1) Create or Clone a Session for every user you want to test.

(2) Save and load session setup

(3) Specify the session characteristics (Header(s) and / or Parameter(s) to replace)

(4) Set Filters if needed

(5) Start / Stop and Pause Auth Analyzer

(6) Specify table filter

(7) Navigate through Web App with another user and track results of the repeated requests

(8) Export table data to XML or HTML

(9) Manually analyze original and repeated requests / responses 


![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/complete_gui.png)


## Sample Usage

### Session Header and CSRF Token Parameter
Define a Cookie header and a CSRF token (with auto value extract). The CSRF token value will be extracted if it is present in an HTML Input Tag, a Set-Cookie Header or a JSON Response of the given session.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/session_header_with_csrf_token.png)

### Auto extract session Cookie
Define the username and password as a static value. The session cookie name must be defined as auto extract. Verify that you start navigating through the application with no session cookie set. Login to the web app. The Auth Analyzer will repeat the login request with the static parameters and automatically gets the session by the Set-Cookie header. This Cookie will be used for further requests of the given session. The defined Cookie will be treated as a parameter and therefore no Cookie Header must be defined.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/auto_extract_session_id.png)

### Auto extract from JavaScript variable
Since the "Auto Extract" method only works on "HTML Input Fields", "JSON Objects" or "Set-Cookie Headers" we must use the generic extraction method called "From To String". With this extraction method we can extract any value from a response if it is located between a unique starting and ending string. The Auth Analyzer provides a context menu method to set the "From String" and "To String" automatically. Just mark the String you want to extract and set as "From-To Extract" by the context menu.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/auto_extract_csrftoken_from_js_var.png)

### Auto extract and insert a Bearer Token
Since the Authorization Header is not treated as a parameter (as it is done with the Cookie Header), we can use a header insertion point to achieve what we want. Just mark and right click the value you want to replace in the specified header. The "defaultvalue" will be used if no parameter value is extracted yet.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/autp_extract_and_insert_bearer_token.png)

### Test several roles at a time
Just create as many sessions as you want to test several roles at a time. 

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/several_sessions.png)

### Refresh Auto Exracted Parameter Value
Just press "Renew" on the session status panel or repeat the affected request by the context menu (mouse right click in the table entry). Hint: The login request(s) can be marked and filtered afterwards.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/renew_session.png)

### Test idempotent Operations
Original Requests can be dropped for testing idempotent operations.

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/idempotent_operations.png)

## Parameter Extraction
The Auth Analyzer has the possibility to define parameters which are replaced before the request for the given session will be repeated. The value for the given parameter can be set according to different requirements. Following is possible:
### Auto Extract
The parameter value will be extracted if it occurs in a response with one of the following constraints:

* A response with a **Set-Cookie Header** with a Cookie name set to the defined **Extract Field Name**

* An **HTML Document Response** contains an input field with the name attribute set to the defined **Extract Field Name**

* A **JSON Response** contains a key set to the **Extract Field Name**

### From To String
The parameter will be extracted if the response contains the specified **From String** and **To String** in a line. The From-To String can be set either manually or directly by the corresponding context menu. Just mark the word you want to extract in any response and set as "From-To Extract" for the parameter you like.

### Static Value
A static parameter value can be defined. This can be used for instance for static CSRF tokens or login credentials.
### Prompt for Input
You will be prompted for input if the defined parameter is present in a request. This can be used for instance to set 2FA codes.

## Parameter Replacement
If a value is set (extracted or defined by the user) it will be replaced if the corresponding parameter is present in a request. The conditions for parameter replacements are:
### Replacement Location
The parameter will be replaced if it is present at one of the following locations:

![Auth Analyzer](https://github.com/simioni87/auth_analyzer/blob/main/pics/param_replace_locations.png)

* **In Path** (e.g. /api/user/99/profile --> if a parameter named "user" is presenet, the value "99" will be replaced)

* **URL Parameter** (e.g. email=hans.wurst[a]gmail.com)

* **Cookie Parameter** (e.g. PHPSESSID=mb8rkrcdg8765dt91vpum4u21v)

* **Body Parameter** either URL-Encoded or Multipart Form Data

* **JSON Parameter** (e.g. {"email":"hans.wurst[a]gmail.com"})

## Parameter removement
The defined parameter can be removed completely for instance to test CSRF check mechanisms. 

## Processing Filter
The Auth Analyzer should process two types of requests / responses:

* The response contains a value which must be extracted

* The requested resource should not be accessible by the defined session(s)

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
*	Clone a Session
* Set any amount of Headers to replace / add
* Set Headers to remove
*	Set any amount of parameters to replace
*	Define how the parameter value will be discovered (automatic, static, prompt for input, from to string)
*	Remove a specified parameter
*	Detailed Filter Rules
*	Detailed Status Panel for each Session
* Pause each Session separately
* Renew Auto Extracted Parameter Value automatically
* Repeat Request by context menu
* Table Data Filter
* Table Data Export Functionality
*	Start / Stop / Pause the "Auth Analyzer"
* Pause each Session seperatly
* Restrict session to defined scope
* Filter Requests with same header(s)
* Drop Original Request functionality
*	Detailed view of all processed Requests and Responses
*	Send Header(s) and / or Parameter(s) directly to Auth Analyzer by Context Menu
*	Auto save current configuration
* Save to file and load from file current configuration
