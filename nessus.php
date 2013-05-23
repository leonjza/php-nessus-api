<?php
/**
 * PHP-Nessus-API
 *
 * PHP Version 5
 *
 * @category Core
 * @package  None
 * @author   th3l33k <theninjabag@gmail.com>
 * @license  http://theninjabag.net/ None
 * @link     http://theninjabag.net/
 */

/**
 * This class will handle all off the Nessus API related functions
 *
 * @category Nessus_Class
 * @package  None
 * @author   th3l33k <theninjabag@gmail.com>
 * @license  http://theninjabag.net/ None
 * @link     http://theninjabag.net/
 */
class NessusInterface
{

    /**
     * Instantiate the instance
     *
     * @param string $url      The host to which we should connect.
     * @param string $port     The port to which we should connect.
     * @param string $username The username
     * @param string $password The that would be used.
     *
     * @return nothing
     */
    public function __construct($url, $port, $username, $password)
    {

        // Check that we have a valid URL here.
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            throw new Exception("Invalid URL for NessusInterface Object", 1);
        }

        // Check that we have a valid port here.
        if (!is_numeric($port) || ( 0 > $port ) || ( $port > 65535 )) {
            throw new Exception("Invalid port for NessusInterface Object", 1);
        }

        // Prepare the full url
        $this->url = rtrim($url, "/") . ":" . $port;
        $this->username = $username;
        $this->password = $password;

        // Perform the login and set the token that will be used.
        $this->login();
    }

    /**
     * Class deconstructor used once all references to this Class is cleared. We want to log out cleanly.
     *
     * @return void
     */
    public function __destruct()
    {

        $this->logout();
    }

    /**
     * Check a cURL response and its headers to ensure that it was successfull.
     *
     * @param string $ch     The cURL connection object.
     * @param string $result The result from a cURL request
     *
     * @return nothing
     */
    private function checkResponse($ch, $result)
    {

        $this->http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($this->http_status == 403) {

            throw new Exception("Unauthorized Request to " . $this->call, 1);
        }

        if ($this->http_status <> 200) {

            throw new Exception("Failed/Timedout API Request to " . $this->call, 1);
        }

        // Parse the XML to check the status and read the error if required
        $xml = new SimpleXMLElement($result);
        if ($xml->status <> "OK") {

            throw new Exception("Error Processing Request. Error was: " . $xml->contents, 1);
        }
    }

    /**
     * Generate a random sequence number betwee 1 and 65535. This is used for API call synchronization checks.
     *
     * @return nothing
     */
    private function setSequence()
    {

        $this->sequence = rand(1, 65535);
    }

    /**
     * Check that the returned sequence number matched the sequence that was sent.
     *
     * @param string $sequence The received sequence number from the API return
     *
     * @return nothing
     */
    private function checkSequence($sequence)
    {

        if ($sequence <> $this->sequence) {

            throw new Exception(
                "Out of sequence request calling " . $this->call . ". Got #$sequence instead of #" . $this->sequence,
                1
            );
        }
    }

    /**
     * Login to the Nessus Server preserving the token in this->token
     *
     * @return nothing
     */
    private function login()
    {

        // Set a new the Sequence
        $this->setSequence();

        //set POST variables
        $fields_string = null;
        $fields = array(
            "login"     =>urlencode($this->username),
            "password"  =>urlencode($this->password),
            "seq"       =>urlencode($this->sequence)
        );

        //Set RPC funtion to URL
        $this->call = $this->url . "/login/";

        //url-ify the data for the POST
        foreach ($fields as $key=>$value) {
            $fields_string .= $key."=".$value."&";
        }
        rtrim($fields_string, "&");

        //open connection
        $ch = curl_init();

        //set the url, number of POST vars, POST data
        curl_setopt($ch, CURLOPT_URL, $this->call);
        curl_setopt($ch, CURLOPT_POST,   count($fields));
        curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT,  5); //Give the Nessus box 5 seconds to respond, or else...

        //execute post
        $result = curl_exec($ch);

        // Check what we got back
        $this->checkResponse($ch, $result);

        //close connection
        curl_close($ch);

        // Parse the XML and populate the Object
        $xml = new SimpleXMLElement($result);

        // Check the response Sequence Number
        $this->checkSequence((string)$xml->seq);

        // Set the session token
        $this->token = (string)$xml->contents->token;
        $this->token_refreshed = false; // Something to be used later for re-authentication
    }

    /**
     * Log out of the scanner, effectively destroying the token
     *
     * @return nothing
     */
    private function logout()
    {

        // Set a new the Sequence
        $this->setSequence();

        //set POST variables
        $fields_string = null;
        $fields = array(
            "token"  =>urlencode($this->token),
            "seq"    =>urlencode($this->sequence)
        );
        //Set RPC funtion to URL
        $this->call = $this->url . "/logout/";

        //url-ify the data for the POST
        foreach ($fields as $key=>$value) {
            $fields_string .= $key."=".$value."&";
        }
        rtrim($fields_string, "&");

        //open connection
        $ch = curl_init();

        //set the url, number of POST vars, POST data
        curl_setopt($ch, CURLOPT_URL, $this->call);
        curl_setopt($ch, CURLOPT_POST,   count($fields));
        curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

        //execute post
        $result = curl_exec($ch);

        // Check what we got back
        $this->checkResponse($ch, $result);

        //close connection
        curl_close($ch);

        //Build the return array
        $xml = new SimpleXMLElement($result);

        // Check the response Sequence Number
        $this->checkSequence((string)$xml->seq);

        // Unset the session token
        $this->token = null;
    }

    /**
     * Retreive a list of all the reports in the scanner.
     *
     * @return An array containing the report list
     */
    public function reportList()
    {

        // Set a new the Sequence
        $this->setSequence();

        //set POST variables
        $fields_string = null;
        $fields = array(
            "token" => urlencode($this->token),
            "seq"    =>urlencode($this->sequence)
        );

        //url-ify the data for the POST
        foreach ($fields as $key=>$value) {
            $fields_string .= $key."=".$value."&";
        }
        rtrim($fields_string, "&");

        //Set RPC funtion to URL
        $this->call = $this->url . "/report/list/";

        //open connection
        $ch = curl_init();

        //set the url, number of POST vars, POST data
        curl_setopt($ch, CURLOPT_URL, $this->call);
        curl_setopt($ch, CURLOPT_POST,   count($fields));
        curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

        //execute post
        $result = curl_exec($ch);

        // Check what we got back
        $this->checkResponse($ch, $result);

        //close connection
        curl_close($ch);

        //Build the return array
        $xml = new SimpleXMLElement($result);

        // Check the response Sequence Number
        $this->checkSequence((string)$xml->seq);

        // Prepare the return array
        $values = array();
        foreach ($xml->contents->reports->report as $report) {

            $values["reports"][(string)$report->name]["status"] = (string)$report->status;
            $values["reports"][(string)$report->name]["readableName"] = (string)$report->readableName;
            $values["reports"][(string)$report->name]["timestamp"] = (string)$report->timestamp;
        }

        //Return what we get
        return($values);
    }

    /**
     * Retreive technical details about the scanner such as Server Version etc.
     *
     * @return An array containing the server details
     */
    public function feed()
    {

        // Set a new the Sequence
        $this->setSequence();

        //set POST variables
        $fields_string = null;
        $fields = array(
            "token"  =>urlencode($this->token),
            "seq"    =>urlencode($this->sequence)
        );

        //url-ify the data for the POST
        foreach ($fields as $key=>$value) {
            $fields_string .= $key."=".$value."&";
        }
        rtrim($fields_string, "&");

        //Set RPC funtion to URL
        $this->call = $this->url . "/feed/";

        //open connection
        $ch = curl_init();

        //set the url, number of POST vars, POST data
        curl_setopt($ch, CURLOPT_URL, $this->call);
        curl_setopt($ch, CURLOPT_POST,   count($fields));
        curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

        //execute post
        $result = curl_exec($ch);

        // Check what we got back
        $this->checkResponse($ch, $result);

        //close connection
        curl_close($ch);

        //Build the return array
        $xml = new SimpleXMLElement($result);

        // Check the response Sequence Number
        $this->checkSequence((string)$xml->seq);

        $values= array (
            "feed"               => (string)$xml->contents->feed,
            "server_version"     => (string)$xml->contents->server_version,
            "web_server_version" => (string)$xml->contents->web_server_version,
            "expiration"         => (string)$xml->contents->expiration,
            "msp"                => (string)$xml->contents->msp,
            "loaded_plugin_set"  => (string)$xml->contents->loaded_plugin_set,
            "expiration_time"    => (string)$xml->contents->expiration_time
        );

        //Return what we got
        return($values);
    }

    /**
     * Retreive a list of configured policies for the scanner.
     *
     * @return An array containing the policy names and numerica references
     */
    public function policyList()
    {

        // Set a new the Sequence
        $this->setSequence();

        //set POST variables
        $fields_string = null;
        $fields = array(
            "token"  =>urlencode($this->token),
            "seq"    =>urlencode($this->sequence)
        );

        //url-ify the data for the POST
        foreach ($fields as $key=>$value) {
            $fields_string .= $key."=".$value."&";
        }
        rtrim($fields_string, "&");

        //Set RPC funtion to URL
        $this->call = $this->url . "/policy/list/";

        //open connection
        $ch = curl_init();

        //set the url, number of POST vars, POST data
        curl_setopt($ch, CURLOPT_URL, $this->call);
        curl_setopt($ch, CURLOPT_POST,   count($fields));
        curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

        //execute post
        $result = curl_exec($ch);

        // Check what we got back
        $this->checkResponse($ch, $result);

        //close connection
        curl_close($ch);

        //Build the return array
        $xml = new SimpleXMLElement($result);

        // Check the response Sequence Number
        $this->checkSequence((string)$xml->seq);

        //##TODO: Lots more information available here. Should maybe make a seperate details() call.
        $values = array();
        foreach ($xml->contents->policies->policy as $policy) {

            $values["policies"][(string)$policy->policyID] = (string)$policy->policyName;
        }

        //Return what we got
        return($values);
    }

    /**
     * Retreive a list of the current running scans as well as the configured templates.
     *
     * @return An array containing the policy names and their numerical references
     */
    public function scanList()
    {

        // Set a new the Sequence
        $this->setSequence();

        //set POST variables
        $fields_string = null;
        $fields = array(
            "token"  =>urlencode($this->token),
            "seq"    =>urlencode($this->sequence)
        );

        //url-ify the data for the POST
        foreach ($fields as $key=>$value) {
            $fields_string .= $key."=".$value."&";
        }
        rtrim($fields_string, "&");

        //Set RPC funtion to URL
        $this->call = $this->url . "/scan/list/";

        //open connection
        $ch = curl_init();

        //set the url, number of POST vars, POST data
        curl_setopt($ch, CURLOPT_URL, $this->call);
        curl_setopt($ch, CURLOPT_POST,   count($fields));
        curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

        //execute post
        $result = curl_exec($ch);

        // Check what we got back
        $this->checkResponse($ch, $result);

        //close connection
        curl_close($ch);

        //Build the return array
        $xml = new SimpleXMLElement($result);

        // Check the response Sequence Number
        $this->checkSequence((string)$xml->seq);

        $values = array();
        foreach ($xml->contents as $item) {

            foreach ($item->scans->scanList as $scan) {

                foreach ($scan->scan as $details) {

                    $uuid=(string)$details->uuid;
                    $values["currentScans"][$uuid]["readableName"]        = (string)$details->readableName;
                    $values["currentScans"][$uuid]["owner"]               = (string)$details->owner;
                    $values["currentScans"][$uuid]["start_time"]          = (string)$details->start_time;
                    $values["currentScans"][$uuid]["status"]              = (string)$details->status;
                    $values["currentScans"][$uuid]["completion_current"]  = (string)$details->completion_current;
                    $values["currentScans"][$uuid]["completion_total"]    = (string)$details->completion_total;
                }
            }
            foreach ($item->templates->template as $template) {

                $uuid=(string)$template->name;
                $values["templates"][$uuid]["policy_id"]     = (string)$template->policy_id;
                $values["templates"][$uuid]["readableName"]  = (string)$template->readableName;
                $values["templates"][$uuid]["owner"]         = (string)$template->owner;
                $values["templates"][$uuid]["startTime"]     = (string)$template->startTime;
                $values["templates"][$uuid]["target"]        = (string)$template->target;
            }
        }

        //Return what we get
        return($values);
    }

    /**
     * Schedule a new scan to be run
     *
     * @param string $template_name A name for the scheduled scan
     * @param int    $policy_id     The policy id to be used.
     * @param string $target        A newline seperated list of Subnets to scan
     * @param string $starttime     The time the scan should start
     * @param string $freq          Optionally, a frequency of the scan.
     *
     * @return A array confirming the scans schedule request.
     */
    public function newScanTemplate($template_name,$policy_id,$target,$starttime,$freq="FREQ=ONETIME")
    {

        //##TODO: Validate the fields we received and throw errors? Or Leave Validation upto the client?

        // Set a new the Sequence
        $this->setSequence();

        $fields_string = null;
        $fields = array(
            "template_name" =>urlencode($template_name),
            "rRules"        =>urlencode($freq),
            "startTime"     =>urlencode($starttime),
            "policy_id"     =>urlencode($policy_id),
            "target"        =>urlencode($target),
            "token"         =>urlencode($this->token),
            "seq"    =>urlencode($this->sequence)
        );

        //url-ify the data for the POST
        foreach ($fields as $key=>$value) {
            $fields_string .= $key."=".$value."&";
        }
        rtrim($fields_string, "&");

        //Set RPC funtion to URL
        $this->call = $this->url . "/scan/template/new/";

        //open connection
        $ch = curl_init();

        //set the url, number of POST vars, POST data
        curl_setopt($ch, CURLOPT_URL, $this->call);
        curl_setopt($ch, CURLOPT_POST,   count($fields));
        curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

        //execute post
        $result = curl_exec($ch);

        // Check what we got back
        $this->checkResponse($ch, $result);

        //close connection
        curl_close($ch);

        //Build the return array
        $xml = new SimpleXMLElement($result);

        // Check the response Sequence Number
        $this->checkSequence((string)$xml->seq);

        $values = array();
        foreach ($xml->contents->template as $response) {
            $values["response"]["name"]         = (string)$response->name;
            $values["response"]["policy_id"]    = (string)$response->policy_id;
            $values["response"]["readableName"] = (string)$response->readableName;
            $values["response"]["owner"]        = (string)$response->owner;
            $values["response"]["target"]       = (string)$response->target;
            $values["response"]["startTime"]    = (string)$response->startTime;
        }


        //Return what we got
        return($values);
    }

    /**
     * Pause a scan
     *
     * @param string $uuid The scan UUID that will be paused
     *
     * @return A array confirming the scans pause request.
     */
    public function scanPause($uuid)
    {

        // Set a new the Sequence
        $this->setSequence();

        //set POST variables
        $fields_string = null;
        $fields = array(
            "token"     =>urlencode($this->token),
            "scan_uuid" =>urlencode($uuid),
            "seq"       =>urlencode($this->sequence)
        );

        //url-ify the data for the POST
        foreach ($fields as $key=>$value) {
            $fields_string .= $key."=".$value."&";
        }
        rtrim($fields_string, "&");

        //Set RPC funtion to URL
        $this->call = $this->url . "/scan/pause/";

        //open connection
        $ch = curl_init();

        //set the url, number of POST vars, POST data
        curl_setopt($ch, CURLOPT_URL, $this->call);
        curl_setopt($ch, CURLOPT_POST,   count($fields));
        curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

        //execute post
        $result = curl_exec($ch);

        // Check what we got back
        $this->checkResponse($ch, $result);

        //close connection
        curl_close($ch);

        //Build the return array
        $xml = new SimpleXMLElement($result);

        // Check the response Sequence Number
        $this->checkSequence((string)$xml->seq);

        $values = array();
        foreach ($xml->contents->scan as $scan) {
            $values["response"]["uuid"]               = (string)$scan->uuid;
            $values["response"]["readableName"]       = (string)$scan->readableName;
            $values["response"]["owner"]              = (string)$scan->owner;
            $values["response"]["start_time"]         = (string)$scan->start_time;
            $values["response"]["status"]             = (string)$scan->status;
            $values["response"]["completion_current"] = (string)$scan->completion_current;
            $values["response"]["completion_total"]   = (string)$scan->completion_total;
        }

        //Return what we got
        return($values);
    }

    /**
     * Resume a scan
     *
     * @param string $uuid The scan UUID that will be resumed
     *
     * @return A array confirming the scans resume request.
     */
    public function scanResume($uuid)
    {

        // Set a new the Sequence
        $this->setSequence();

        //set POST variables
        $fields_string = null;
        $fields = array(
            "token"     =>urlencode($this->token),
            "scan_uuid" =>urlencode($uuid),
            "seq"       =>urlencode($this->sequence)
        );

        //url-ify the data for the POST
        foreach ($fields as $key=>$value) {
            $fields_string .= $key."=".$value."&";
        }
        rtrim($fields_string, "&");

        //Set RPC funtion to URL
        $this->call = $this->url . "/scan/resume/";

        //open connection
        $ch = curl_init();

        //set the url, number of POST vars, POST data
        curl_setopt($ch, CURLOPT_URL, $this->call);
        curl_setopt($ch, CURLOPT_POST,   count($fields));
        curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

        //execute post
        $result = curl_exec($ch);

        // Check what we got back
        $this->checkResponse($ch, $result);

        //close connection
        curl_close($ch);

        //Build the return array
        $xml = new SimpleXMLElement($result);

        // Check the response Sequence Number
        $this->checkSequence((string)$xml->seq);

        $values = array();
        foreach ($xml->contents->scan as $scan) {

            $values["response"]["uuid"]               = (string)$scan->uuid;
            $values["response"]["readableName"]       = (string)$scan->readableName;
            $values["response"]["owner"]              = (string)$scan->owner;
            $values["response"]["start_time"]         = (string)$scan->start_time;
            $values["response"]["status"]             = (string)$scan->status;
            $values["response"]["completion_current"] = (string)$scan->completion_current;
            $values["response"]["completion_total"]   = (string)$scan->completion_total;
        }

        //Return what we got
        return($values);
    }

    /**
     * Stop a scan
     *
     * @param string $uuid The scan UUID that will be stopped
     *
     * @return A array confirming the scans stop request.
     */
    public function scanStop($uuid)
    {

        // Set a new the Sequence
        $this->setSequence();

        //set POST variables
        $fields_string = null;
        $fields = array(
            "token"     =>urlencode($this->token),
            "scan_uuid" =>urlencode($uuid),
            "seq"       =>urlencode($this->sequence)
        );

        //url-ify the data for the POST
        foreach ($fields as $key=>$value) {
            $fields_string .= $key."=".$value."&";
        }
        rtrim($fields_string, "&");

        //Set RPC funtion to URL
        $this->call = $this->url . "/scan/stop/";

        //open connection
        $ch = curl_init();

        //set the url, number of POST vars, POST data
        curl_setopt($ch, CURLOPT_URL, $this->call);
        curl_setopt($ch, CURLOPT_POST,   count($fields));
        curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

        //execute post
        $result = curl_exec($ch);

        // Check what we got back
        $this->checkResponse($ch, $result);

        //close connection
        curl_close($ch);

        //Build the return array
        $xml = new SimpleXMLElement($result);

        // Check the response Sequence Number
        $this->checkSequence((string)$xml->seq);

        $values = array();
        foreach ($xml->contents->scan as $scan) {

            $values["response"]["uuid"]               = (string)$scan->uuid;
            $values["response"]["readableName"]       = (string)$scan->readableName;
            $values["response"]["owner"]              = (string)$scan->owner;
            $values["response"]["start_time"]         = (string)$scan->start_time;
            $values["response"]["status"]             = (string)$scan->status;
            $values["response"]["completion_current"] = (string)$scan->completion_current;
            $values["response"]["completion_total"]   = (string)$scan->completion_total;
        }

        //Return what we got
        return($values);
    }

    /**
     * Delete a scan template.
     *
     * @param string $template_name The scan UUID that will be deleted
     *
     * @return A array confirming the scans delete request.
     */
    public function templateDelete($template_name)
    {

        // Set a new the Sequence
        $this->setSequence();

        //set POST variables
        $fields_string = null;
        $fields = array(
            "token"     =>urlencode($this->token),
            "template"  =>urlencode($template_name),
            "seq"       =>urlencode($this->sequence)
        );

        //url-ify the data for the POST
        foreach ($fields as $key=>$value) {
            $fields_string .= $key."=".$value."&";
        }
        rtrim($fields_string, "&");

        //Set RPC funtion to URL
        $this->call = $this->url . "/scan/template/delete/";

        //open connection
        $ch = curl_init();

        //set the url, number of POST vars, POST data
        curl_setopt($ch, CURLOPT_URL, $this->call);
        curl_setopt($ch, CURLOPT_POST,   count($fields));
        curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

        //execute post
        $result = curl_exec($ch);

        // Check what we got back
        $this->checkResponse($ch, $result);

        //close connection
        curl_close($ch);

        //Build the return array
        $xml = new SimpleXMLElement($result);

        // Check the response Sequence Number
        $this->checkSequence((string)$xml->seq);

        $values = array();
        foreach ($xml->contents->template as $response) {

            $values["response"]["name"]         = (string)$response->name;
            $values["response"]["policy_id"]    = (string)$response->policy_id;
            $values["response"]["readableName"] = (string)$response->readableName;
            $values["response"]["owner"]        = (string)$response->owner;
            $values["response"]["target"]       = (string)$response->target;
            $values["response"]["startTime"]    = (string)$response->startTime;
            $values["response"]["rRules"]       = (string)$response->rRules;
        }

        //Return what we got
        return($values);
    }

    /**
     * Launch a scan template now.
     *
     * @param string $template_name The scan UUID that will be launched
     *
     * @return A array confirming the scans launch request.
     */
    public function templateLaunch($template_name)
    {

        // Set a new the Sequence
        $this->setSequence();

        //set POST variables
        $fields_string = null;
        $fields = array(
            "token"     =>urlencode($this->token),
            "template"  =>urlencode($template_name),
            "seq"       =>urlencode($this->sequence)
        );

        //url-ify the data for the POST
        foreach ($fields as $key=>$value) {
            $fields_string .= $key."=".$value."&";
        }
        rtrim($fields_string, "&");

        //Set RPC funtion to URL
        $this->call = $this->url . "/scan/template/launch/";

        //open connection
        $ch = curl_init();

        //set the url, number of POST vars, POST data
        curl_setopt($ch, CURLOPT_URL, $this->call);
        curl_setopt($ch, CURLOPT_POST,   count($fields));
        curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

        //execute post
        $result = curl_exec($ch);

        // Check what we got back
        $this->checkResponse($ch, $result);

        //close connection
        curl_close($ch);

        //Build the return array
        $xml = new SimpleXMLElement($result);

        // Check the response Sequence Number
        $this->checkSequence((string)$xml->seq);

        $values = array();
        foreach ($xml->contents->scan as $response) {

            $values["response"]["uuid"]         = (string)$response->uuid;
            $values["response"]["owner"]        = (string)$response->owner;
            $values["response"]["start_time"]   = (string)$response->start_time;
        }

        //Return what we got
        return($values);
    }
}
