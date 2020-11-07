# Auth Analyzer
This Burp Extension helps you to find authorization bugs by repeating Proxy requests with self defined headers and tokens.

## What is it?
The so called “Auth Analyzer” helps to find authorization bugs. 

## How does it work?
1.	Create a “New Session” for each user role you want to test (e.g. admin, normal_user, unauthenticated, …) 
2.	Paste the session characteristic (e.g. Session Cookie, Authorization Header, …) into the text area “Header(s) to replace”
3.	If needed: Define CSRF Token Name
    
    a. With a dynamic value (the CSRF token value will be automatically grepped if it is present in a HTML-input tag or JSON object of a given response)
    
    b. With a static value (value can be defined)
    
    c. Remove CSRF Token (to test CSRF check mechanism of for other purposes)
    
4.	If needed: Add your preferred “Grep and Replace” Rules (a start and stop string can be defined for Grep and Replace. Each grepped value will be replaced within the defined Replace rule of the given session).
5. Define Filters (only relevant requests should be processed)
5.	Start the “Auth Analyzer”. 

  *	Each Request will be displayed in a table. 
  *	I will easy see for each session if you have a BYPASS or a POTENTIAL_BYPASS for each request.

## Processing Filter
The “Auth Analyzer” should only process Request which eighter have a CSRF Token in it or should only be accessible for authorized users. For this reason, following filters can be defined:
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
* Send marked text directly to "Header(s) to replace" text field by context menu item
