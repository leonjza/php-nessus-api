<?php
#--- Check to see if the query was ok
#
#  Requires:
#                 - XML reponse to be checked
#  Returns:
#                 - Boolean (TRUE or FALSE)
function check_status($xml)
   {
      $loginstatus = $xml->status;
      if($loginstatus == 'OK') { return TRUE; } else { return FALSE; }
   }

#--- Safety check to see if we did not loose the token somehow
#
#  Requires:
#                 - Raw cURL reponse
#  Returns:
#                 - Boolean (TRUE or FALSE)
function check_auth($curl)
   {
      if(preg_match("/200 Unauthorized/",$curl)) {return TRUE; } else { return FALSE; }
   }

#-- Funtion used to perform a login and pass back the token.
#
#  Requires: 
#                    -  Server URL
#                    -  Username
#                    -  Password
#  Returns:   
#                    - Array  (  'status' => value
#                                'token'  => value  )
function perform_login($url,$login,$password)
   {
      //set POST variables
      $fields_string = NULL;
      $fields = array(
                        'login'     =>urlencode($login),
                        'password'  =>urlencode($password)
                     );
      //Set RPC funtion to URL
      $url .= 'login/';

      //url-ify the data for the POST
      foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
      rtrim($fields_string,'&');

      //open connection
      $ch = curl_init();

      //set the url, number of POST vars, POST data
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_POST,   count($fields));
      curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);
      curl_setopt($ch, CURLOPT_CONNECTTIMEOUT,  5); //Give the Nessus box 5 seconds to respond, or else...

      //execute post
      $result = curl_exec($ch);

      //close connection
      curl_close($ch);
      
      if($result == FALSE) 
         {  
            $_token = "Nessus is dead @$url"; //Should nessus timeout well get `FALSE`, so here well just have to handle it. 
            $values = array ( 'status'  => (string)$_token );
         } else
            {
               //Build the return array
               $xml = new SimpleXMLElement($result);
               $loginstatus = $xml->status;
               if(check_status($xml)) { $_token = $xml->contents->token; } else { $_token = 'Login Failed'; }
               $values = array (
                                 'status' => (string)$loginstatus,
                                 'token'  => (string)$_token
                              );
            }

      //Return what we got
      return($values);
   }

#-- Funtion used to perform a logout making the used token invalid.
#
#  Requires: 
#                    -  Server URL
#                    -  Token
#  Returns:   
#                    - Array  (  'status' => value
#                                'result' => value  )
function perform_logout($url,$token)
   {
      //set POST variables
      $fields_string = NULL;
      $fields = array(
                        'token'  =>urlencode($token)
                     );
      //Set RPC funtion to URL
      $url .= 'logout/';

      //url-ify the data for the POST
      foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
      rtrim($fields_string,'&');

      //open connection
      $ch = curl_init();

      //set the url, number of POST vars, POST data
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_POST,   count($fields));
      curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

      //execute post
      $result = curl_exec($ch);

      //close connection
      curl_close($ch);

      //Last Auth check
      if(check_auth($result)) { break; } else {}

      //Build the return array         
      $xml = new SimpleXMLElement($result);
      $loginstatus = $xml->status;
      $values= array (
                        'status' => (string)$loginstatus,
                        'result' => (string)$xml->contents
                     );
      
      //Return what we got
      return($values);
   }

#-- Funtion used to retreive server information.
#   Seems to work even when unauthenticated unlike API document states
#
#  Requires: 
#                    -  Server URL
#                    -  Token
#  Returns:   
#                    - Array  (  'status'             => value
#                                'feed'               => value
#                                'server_version'     => value
#                                'web_server_version' => value
#                                'expiration'         => value   )
function get_feed($url,$token)
   {
      //set POST variables
      $fields_string = NULL;
      $fields = array(
                        'token'  =>urlencode($token)
                     );

      //url-ify the data for the POST
      foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
      rtrim($fields_string,'&');

      //Set RPC funtion to URL
      $url .= 'feed/';

      //open connection
      $ch = curl_init();

      //set the url, number of POST vars, POST data
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_POST,   count($fields));
      curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

      //execute post
      $result = curl_exec($ch);

      //Last Auth check 
      if(check_auth($result)) 
         {  
            $values['status'] = 'Got 200 not authorized';
            return($values);
            exit;
         }


      //close connection
      curl_close($ch);

      //Build the return array
      $xml = new SimpleXMLElement($result);
      if(check_status($xml))
         { 
            $values= array (
                              'status'             => (string)$xml->status,
                              'feed'               => (string)$xml->contents->feed,
                              'server_version'     => (string)$xml->contents->server_version,
                              'web_server_version' => (string)$xml->contents->web_server_version,
                              'expiration'         => (string)$xml->contents->expiration
                           );
         } else
            {
               $values= array (
                                 'status' => (string)$xml->status 
                              );
            }

      //Return what we got
      return($values);
   }

#-- Funtion used to retreive a list of reports on the server.
#
#  Requires: 
#                    -  Server URL
#                    -  Token
#  Returns:   
#                    - Array  (  'status' => value
#                                'web_server_version' => value
#                                'expiration' => value   )
function reports_list($url,$token)
   {
      //set POST variables
      $fields_string = NULL;
      $fields = array(
                        'token'=>urlencode($token)
                     );

      //url-ify the data for the POST
      foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
      rtrim($fields_string,'&');

      //Set RPC funtion to URL
      $url .= 'report/list/';

      //open connection
      $ch = curl_init();

      //set the url, number of POST vars, POST data
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_POST,   count($fields));
      curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

      //execute post
      $result = curl_exec($ch);

      //Last Auth check 
      if(check_auth($result)) 
         {  
            $values['status'] = 'Got 200 not authorized';
            return($values);
            exit;
         }

      //close connection
      curl_close($ch);

      //Build the return array
      $xml = new SimpleXMLElement($result);
      if(check_status($xml))
         { 
            $values= array (
                              'status' => (string)$xml->status,
                           );
         } else
            {
               $values= array (
                                 'status' => (string)$xml->status 
                              );
            }

      //Return what we get
      return($values);
   }

#-- Funtion used to retreive a list of the configured policies in the server. 
#   This is a very small summary. We only really want the name and number.
#
#  Requires: 
#                    -  Server URL
#                    -  Token
#  Returns:   
#                    - Array  (  'status'    => value
#                                'policies'  => Array (  
#                                                     '{policy id}'  => value  )
function policy_list($url,$token)
   {
      $list[] = NULL;
      //set POST variables
      $fields_string = NULL;
      $fields = array(
                        'token'  =>urlencode($token)
                     );

      //url-ify the data for the POST
      foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
      rtrim($fields_string,'&');

      //Set RPC funtion to URL
      $url .= 'policy/list/';

      //open connection
      $ch = curl_init();

      //set the url, number of POST vars, POST data
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_POST,   count($fields));
      curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

      //execute post
      $result = curl_exec($ch);

      //Last Auth check 
      if(check_auth($result)) 
         {  
            $values['status'] = 'Got 200 not authorized';
            return($values);
            exit;
         }

      //close connection
      curl_close($ch);

      //Build the return array
      $xml = new SimpleXMLElement($result);

      if(check_status($xml))
         { 
            foreach($xml->contents->policies->policy as $policy) 
               {
                  $policyID = (string)$policy->policyID;
                  $values['policies'][$policyID] = (string)$policy->policyName;
               }
            $values['status'] = 'OK'; 
         } else
            {
               $values= array (
                                 'status' => (string)$xml->status 
                              );
            }

      //Return what we got
      return($values);
   }

#-- Funtion used to retreive a list current / completed scans.
#
#  Requires: 
#                    -  Server URL
#                    -  Token
#  Returns:
#                    -  Array (  'currentScans' => Array 
#                                                        (  '{uuid}' =>
#                                                                    'readableName  => value
#                                                                    'owner'        => value
#                                                                    'start_time'   => value
#                                                                    'status'       => value )
#                                'pastScans'    => Array
#                                                        (  '{uuid}' =>
#                                                                    'policy_id'    => value
#                                                                    'readableName' => value
#                                                                    'owner'        => value
#                                                                    'startTime'    => value
#                                                                    'target'       => value )
#                                'status'       => value 
#                             )
function scan_list($url,$token)
   {
      $list[] = NULL;
      //set POST variables
      $fields_string = NULL;
      $fields = array(
                        'token'  =>urlencode($token)
                     );

      //url-ify the data for the POST
      foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
      rtrim($fields_string,'&');

      //Set RPC funtion to URL
      $url .= 'scan/list/';

      //open connection
      $ch = curl_init();

      //set the url, number of POST vars, POST data
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_POST,   count($fields));
      curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

      //execute post
      $result = curl_exec($ch);

      //Last Auth check 
      if(check_auth($result)) 
         {  
            $values['status'] = 'Got 200 not authorized';
            return($values);
            exit;
         }

      //close connection
      curl_close($ch);

      //Build the return array
      $xml = new SimpleXMLElement($result);

      if(check_status($xml))
         { 
            foreach($xml->contents as $item) //Start iterating over the actual content of the returned XML
               {
                  foreach($item->scans->scanList as $scan) //Current Scans are in this hierarchy.
                     {
                        foreach($scan->scan as $details) //Iterate over these scans.
                           {
                              $uuid=(string)$details->uuid;
                              $values['currentScans'][$uuid]['readableName']  = (string)$details->readableName;
                              $values['currentScans'][$uuid]['owner']         = (string)$details->owner;
                              $values['currentScans'][$uuid]['start_time']    = (string)$details->start_time;
                              $values['currentScans'][$uuid]['status']        = (string)$details->status;
                           }
                     }
                  foreach($item->templates->template as $template) //Past Scan templates are shown from this hierarchy.
                     {
                        $uuid=(string)$template->name;
                        $values['pastScans'][$uuid]['policy_id']     = (string)$template->policy_id;
                        $values['pastScans'][$uuid]['readableName']  = (string)$template->readableName;
                        $values['pastScans'][$uuid]['owner']         = (string)$template->owner;
                        $values['pastScans'][$uuid]['startTime']     = (string)$template->startTime;
                        $values['pastScans'][$uuid]['target']        = (string)$template->target;
                     }
               }
            $values['status'] = 'OK'; 
         } else
            {
               $values= array (
                                 'status' => (string)$xml->status 
                              );
            }

      //Return what we get
      return($values);
   }

#-- Funtion used to schedule a new scan 
#
#  Requires: 
#                    -  Server URL
#                    -  Token
#                    -  Template Name
#                    -  Policy_id
#                    -  Target
#                    -  Start time (ISO format) i.e: 20100117T151242
#                    -  Reccurance Rule. Defaults to "RRULE=:FREQ=ONETIME;"
#  Returns:
#                    -  Array (  'status'    => value
#                                'response'  => Array 
#                                                     (
#                                                        'name'         => value
#                                                        'policy_id'    => value
#                                                        'readableName' => value
#                                                        'owner'        => value
#                                                        'target'       => value
#                                                        'startTime'    => value )
#                             ) 
function scan_template_new($url,$token,$template_name,$policy_id,$target,$starttime,$freq="RRULE:FREQ=ONETIME")
   {
      $list[] = NULL;
      //set POST variables
      $fields_string = NULL;
      $fields = array(
                        'token'           =>urlencode($token),
                        'template_name'   =>urlencode($template_name),
                        'policy_id'       =>urlencode($policy_id),
                        'target'          =>urlencode($target),
                        'startTime'       =>urlencode($starttime),
                        'rRule'           =>urlencode($freq)
                     );

      //url-ify the data for the POST
      foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
      rtrim($fields_string,'&');

      //Set RPC funtion to URL
      $url .= 'scan/template/new/';

      //open connection
      $ch = curl_init();

      //set the url, number of POST vars, POST data
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_POST,   count($fields));
      curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

      //execute post
      $result = curl_exec($ch);

      //Last Auth check 
      if(check_auth($result)) 
         {  
            $values['status'] = 'Got 200 not authorized';
            return($values);
            exit;
         }

      //close connection
      curl_close($ch);

      //Build the return array
      $xml = new SimpleXMLElement($result);

      if(check_status($xml))
         { 
            foreach($xml->contents->template as $response)
               {
                  $values['response']['name']         = (string)$response->name;
                  $values['response']['policy_id']    = (string)$response->policy_id;
                  $values['response']['readableName'] = (string)$response->readableName;
                  $values['response']['owner']        = (string)$response->owner;
                  $values['response']['target']       = (string)$response->target;
                  $values['response']['startTime']    = (string)$response->startTime;
               }
            $values['status'] = 'OK'; 
         } else
            {
               $values= array (
                                 'status' => (string)$xml->status 
                              );
            }

      //Return what we got
      return($values);
   }

#-- Funtion used to pause a scan. 
#
#  Requires: 
#                    -  Server URL
#                    -  Token
#                    -  Scan UUID 
#  Returns:
#                    -  Array (  'status'    => value
#                                'response'  => Array 
#                                                     (
#                                                        'uuid'               => value
#                                                        'readableName'       => value
#                                                        'owner'              => value
#                                                        'start_time'         => value
#                                                        'status'             => value
#                                                        'completion_current' => value
#                                                        'completion_total'   => value   )
#                             ) 
function scan_pause($url,$token,$uuid)
   {
      $list[] = NULL;
      //set POST variables
      $fields_string = NULL;
      $fields = array(
                        'token'     =>urlencode($token),
                        'scan_uuid' =>urlencode($uuid)
                     );

      //url-ify the data for the POST
      foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
      rtrim($fields_string,'&');

      //Set RPC funtion to URL
      $url .= 'scan/pause/';

      //open connection
      $ch = curl_init();

      //set the url, number of POST vars, POST data
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_POST,   count($fields));
      curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

      //execute post
      $result = curl_exec($ch);

      //Last Auth check 
      if(check_auth($result)) 
         {  
            $values['status'] = 'Got 200 not authorized';
            return($values);
            exit;
         }

      //close connection
      curl_close($ch);

      //Build the return array
      $xml = new SimpleXMLElement($result);

      if(check_status($xml))
         { 
            foreach($xml->contents->scan as $scan)
               {
                  $values['response']['uuid']               = (string)$scan->uuid;
                  $values['response']['readableName']       = (string)$scan->readableName;
                  $values['response']['owner']              = (string)$scan->owner;
                  $values['response']['start_time']         = (string)$scan->start_time;
                  $values['response']['status']             = (string)$scan->status;
                  $values['response']['completion_current'] = (string)$scan->completion_current;
                  $values['response']['completion_total']   = (string)$scan->completion_total;
               }
            $values['status'] = 'OK'; 
         } else
            {
               $values= array (
                                 'status' => (string)$xml->status 
                              );
            }

      //Return what we got
      return($values);
   }

#-- Funtion used to resume a scan. 
#
#  Requires: 
#                    -  Server URL
#                    -  Token
#                    -  Scan UUID 
#  Returns:
#                    -  Array (  'status'    => value
#                                'response'  => Array 
#                                                     (
#                                                        'uuid'               => value
#                                                        'readableName'       => value
#                                                        'owner'              => value
#                                                        'start_time'         => value
#                                                        'status'             => value
#                                                        'completion_current' => value
#                                                        'completion_total'   => value   )
#                             ) 
function scan_resume($url,$token,$uuid)
   {
      $list[] = NULL;
      //set POST variables
      $fields_string = NULL;
      $fields = array(
                        'token'     =>urlencode($token),
                        'scan_uuid' =>urlencode($uuid)
                     );

      //url-ify the data for the POST
      foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
      rtrim($fields_string,'&');

      //Set RPC funtion to URL
      $url .= 'scan/resume/';

      //open connection
      $ch = curl_init();

      //set the url, number of POST vars, POST data
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_POST,   count($fields));
      curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

      //execute post
      $result = curl_exec($ch);

      //Last Auth check 
      if(check_auth($result)) 
         {  
            $values['status'] = 'Got 200 not authorized';
            return($values);
            exit;
         }

      //close connection
      curl_close($ch);

      //Build the return array
      $xml = new SimpleXMLElement($result);

      if(check_status($xml))
         { 
            foreach($xml->contents->scan as $scan)
               {
                  $values['response']['uuid']               = (string)$scan->uuid;
                  $values['response']['readableName']       = (string)$scan->readableName;
                  $values['response']['owner']              = (string)$scan->owner;
                  $values['response']['start_time']         = (string)$scan->start_time;
                  $values['response']['status']             = (string)$scan->status;
                  $values['response']['completion_current'] = (string)$scan->completion_current;
                  $values['response']['completion_total']   = (string)$scan->completion_total;
               }
            $values['status'] = 'OK'; 
         } else
            {
               $values= array (
                                 'status' => (string)$xml->status 
                              );
            }

      //Return what we got
      return($values);
   }

#-- Funtion used to stop a scan. 
#
#  Requires: 
#                    -  Server URL
#                    -  Token
#                    -  Scan UUID 
#  Returns:
#                    -  Array (  'status'    => value
#                                'response'  => Array 
#                                                     (
#                                                        'uuid'               => value
#                                                        'readableName'       => value
#                                                        'owner'              => value
#                                                        'start_time'         => value
#                                                        'status'             => value
#                                                        'completion_current' => value
#                                                        'completion_total'   => value   )
#                             ) 
function scan_stop($url,$token,$uuid)
   {
      $list[] = NULL;
      //set POST variables
      $fields_string = NULL;
      $fields = array(
                        'token'     =>urlencode($token),
                        'scan_uuid' =>urlencode($uuid)
                     );

      //url-ify the data for the POST
      foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
      rtrim($fields_string,'&');

      //Set RPC funtion to URL
      $url .= 'scan/stop/';

      //open connection
      $ch = curl_init();

      //set the url, number of POST vars, POST data
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_POST,   count($fields));
      curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

      //execute post
      $result = curl_exec($ch);

      //Last Auth check 
      if(check_auth($result)) 
         {  
            $values['status'] = 'Got 200 not authorized';
            return($values);
            exit;
         }

      //close connection
      curl_close($ch);

      //Build the return array
      $xml = new SimpleXMLElement($result);

      if(check_status($xml))
         { 
            foreach($xml->contents->scan as $scan)
               {
                  $values['response']['uuid']               = (string)$scan->uuid;
                  $values['response']['readableName']       = (string)$scan->readableName;
                  $values['response']['owner']              = (string)$scan->owner;
                  $values['response']['start_time']         = (string)$scan->start_time;
                  $values['response']['status']             = (string)$scan->status;
                  $values['response']['completion_current'] = (string)$scan->completion_current;
                  $values['response']['completion_total']   = (string)$scan->completion_total;
               }
            $values['status'] = 'OK'; 
         } else
            {
               $values= array (
                                 'status' => (string)$xml->status 
                              );
            }

      //Return what we got
      return($values);
   }

#-- Funtion used to deleted a scheduled scan
#
#  Requires: 
#                    -  Server URL
#                    -  Token
#                    -  Template UUID
#  Returns:
#                    -  Array (  'status'    => value
#                                'response'  => Array 
#                                                     (
#                                                        'name'         => value
#                                                        'policy_id'    => value
#                                                        'readableName' => value
#                                                        'owner'        => value
#                                                        'target'       => value )
#                             ) 
function scan_template_delete($url,$token,$template_name)
   {
      $list[] = NULL;
      //set POST variables
      $fields_string = NULL;
      $fields = array(
                        'token'           =>urlencode($token),
                        'template'        =>urlencode($template_name)
                     );

      //url-ify the data for the POST
      foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
      rtrim($fields_string,'&');

      //Set RPC funtion to URL
      $url .= 'scan/template/delete/';

      //open connection
      $ch = curl_init();

      //set the url, number of POST vars, POST data
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_POST,   count($fields));
      curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

      //execute post
      $result = curl_exec($ch);

      //Last Auth check 
      if(check_auth($result)) 
         {  
            $values['status'] = 'Got 200 not authorized';
            return($values);
            exit;
         }

      //close connection
      curl_close($ch);

      //Build the return array
      $xml = new SimpleXMLElement($result);

      if(check_status($xml))
         { 
            foreach($xml->contents->template as $response)
               {
                  $values['response']['name']         = (string)$response->name;
                  $values['response']['policy_id']    = (string)$response->policy_id;
                  $values['response']['readableName'] = (string)$response->readableName;
                  $values['response']['owner']        = (string)$response->owner;
                  $values['response']['target']       = (string)$response->target;
               }
            $values['status'] = 'OK'; 
         } else
            {
               $values= array (
                                 'status' => (string)$xml->status 
                              );
            }

      //Return what we got
      return($values);
   }

#-- Funtion used to immediately launch a copy of a scheduled scan
#
#  Requires: 
#                    -  Server URL
#                    -  Token
#                    -  Template UUID
#  Returns:
#                    -  Array (  'status'    => value
#                                'response'  => Array 
#                                                     (
#                                                        'uuid'         => value
#                                                        'owner'        => value
#                                                        'start_time'   => value )
#                             ) 
function scan_template_launch($url,$token,$template_name)
   {
      $list[] = NULL;
      //set POST variables
      $fields_string = NULL;
      $fields = array(
                        'token'           =>urlencode($token),
                        'template'        =>urlencode($template_name)
                     );

      //url-ify the data for the POST
      foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
      rtrim($fields_string,'&');

      //Set RPC funtion to URL
      $url .= 'scan/template/launch/';

      //open connection
      $ch = curl_init();

      //set the url, number of POST vars, POST data
      curl_setopt($ch, CURLOPT_URL, $url);
      curl_setopt($ch, CURLOPT_POST,   count($fields));
      curl_setopt($ch, CURLOPT_POSTFIELDS,   $fields_string);
      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,  false);
      curl_setopt($ch, CURLOPT_SSL_VERIFYHOST,  false);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER,  true);

      //execute post
      $result = curl_exec($ch);

      //Last Auth check 
      if(check_auth($result)) 
         {  
            $values['status'] = 'Got 200 not authorized';
            return($values);
            exit;
         }

      //close connection
      curl_close($ch);

      //Build the return array
      $xml = new SimpleXMLElement($result);

      if(check_status($xml))
         { 
            foreach($xml->contents->scan as $response)
               {
                  $values['response']['uuid']         = (string)$response->uuid;
                  $values['response']['owner']        = (string)$response->owner;
                  $values['response']['start_time']   = (string)$response->start_time;
               }
            $values['status'] = 'OK'; 
         } else
            {
               $values= array (
                                 'status' => (string)$xml->status 
                              );
            }

      //Return what we got
      return($values);
   }
?>