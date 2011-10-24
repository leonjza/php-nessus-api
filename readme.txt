#php-nessus-api

Information:
-----------
The Nessus Vulnerability Scanner provides an API interface via XMLRPC.
See: http://www.nessus.org/documentation/nessus_XMLRPC_protocol_guide.pdf

This is simply a set of functions implemented using PHP-Curl to enable querying of this
API using a function and then receiving an array with the applicable data.

Requires:
------------
-	php
-	php-curl
-	php-cli if you plan on running scripts from the cli

Documentation:
--------------
All function responses are documented in the source, detailing the array contents that
will be returned.

Notes:
------
A login must be performed to get a valid token. This token must be used to make any API
queries. Due to the randomness of the token expiry its suggested that a 'perform_login'
and 'perform_logout' is done with each call.


Usage example:
---------------

Simply include ‘nessus.php’ in your script.

Logging in and logging out.
-----------------------------
$login = perform_login($nessusUrl,$nessusUser,$nessusPassword);
if($login['status'] <> 'OK') { die; } else { $token = $login['token']; }

//Do some API calls

perform_logout($nessusUrl,$token);

// Where
//--------
// $nessusUrl = 'http://localhost:8834'; //Nessus Server in quotes i.e. 'https://nessus.server.local:8834/'
// $nessusUser = 'username'; //Nessus Server username in quotes.
// $nessusPassword = 'password'; // Nessus Server password in quotes.

Known issues:
-------------
-	There are probably bugs about.
-	Not all API call have been implemented. Coming soon(tm) as I need them.
-	Probably lack of proper documentation too.