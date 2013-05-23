#php-nessus-api

Information:
-----------
The Nessus Vulnerability Scanner provides an API interface via XMLRPC.
See: http://www.nessus.org/documentation/nessus_XMLRPC_protocol_guide.pdf

This class is simply a set of functions implemented using PHP-Curl to enable querying of this
API using a function and then receiving an array with the applicable data.

Requires:
------------
-	php
-	php-curl
-	php-cli if you plan on running scripts from the cli

Usage example:
---------------

Simply include ‘nessus.php’ in your script.
Then, create a new NessusInterface Object, like:

    try {

        $api = new NessusInterface(
            $__url,
            $__port,
            $__username,
            $__password
        );

    } catch(Exception $e) {

        preprint($e->getMessage());
    }

//Do some API calls. Most methods return some usefull information that should be inspected in your usage case.

    try {

        $api->feed();
        $api->reportList();
        $api->policyList();

        $api->scanList();

    } catch(Exception $e) {

        preprint($e->getMessage());
    }

Known issues:
-------------
-	There are probably bugs about.
-	Not all API call have been implemented. Coming soon(tm) as I need them.
-	Probably lack of proper documentation too.
