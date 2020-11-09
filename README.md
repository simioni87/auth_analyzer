# Auth Analyzer

## What is it?
This Burp Extension helps you to find authorization bugs by repeating Proxy requests with self defined headers and tokens.

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
