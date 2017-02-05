<?php
class secure {
  function flood_protection($status,$type,$interval,$count,$message,$redirect,$logs_folder) {
    if($status > 0) {
      if (!isset($_SESSION)) {
           session_start();
      }
      if(empty($message)) { $message = 'n/a'; }
      if(empty($redirect)) { $redirect = 'n/a'; }
      $filename = date("Y-m-d").'.txt';
      $filepath = $logs_folder."/".$filename;
      $started_contents = 'File: '.$filename.'';
      $started_contents .= 'Created on: '.date("d/m/Y H:i:s").'';
      if(!is_dir($logs_folder)) { mkdir($logs_folder,0777); }
      if(!file_exists($filepath)) { file_put_contents($filepath,$started_contents); }
      $actual_link = "http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
      $date = date("d/m/Y H:i:s");
      $user_ip = $_SERVER['REMOTE_ADDR'];
      if($_SESSION['sa_flood_last_session_request'] > (time() - $interval)){
        if(empty($_SESSION['sa_flood_last_request_count'])){
          $_SESSION['sa_flood_last_request_count'] = 1;
        }elseif($_SESSION['sa_flood_last_request_count'] < $count){
          $_SESSION['sa_flood_last_request_count'] = $_SESSION['sa_flood_last_request_count'] + 1;
        }elseif($_SESSION['sa_flood_last_request_count'] >= $count){
          $contents = '-------------------------------------------------------------------';
            $contents .= 'Flood Protection actived!';
            $contents .= 'User IP Address: '.$user_ip.'';
            $contents .= 'Refresh interval: ~'.$interval.' seconds';
            $contents .= 'Refresh count: > '.$count.' visits';
            $contents .= 'Custom message: '.$message.'';
            $contents .= 'Detected on url: '.$actual_link.'';
            $contents .= 'Redirected to url: '.$redirect.'';
            $contents .= 'Date: '.$date.'';      
            $file_contents = file_get_contents($filepath);
            $new_contents = $file_contents.'';
            $new_contents .= $contents;
            file_put_contents($filepath,$new_contents);
          if($type == "1") {
            die("Flooder!<br/>U banned for $interval seconds.");
          } elseif($type == "2") {
            die("$message<br/>Please refresh page after $interval seconds.");
          } elseif($type == "3") {
            $_SESSION['of_current_link'] = $actual_link;
            header("Location: $redirect");
          } else {
            die("Error security code!");
          }
        }
      }else{
        $_SESSION['sa_flood_last_request_count'] = 1;
      }

      $_SESSION['sa_flood_last_session_request'] = time();
    }
  } 
  
  function log_sql_injections($status,$logs_folder) {
    if($status > 0) {
    $filename = date("Y-m-d").'.txt';
    $filepath = $logs_folder."/".$filename;
    $started_contents = 'File: '.$filename.'';
    $started_contents .= 'Created on: '.date("d/m/Y H:i:s").'';
    if(!is_dir($logs_folder)) { mkdir($logs_folder,0777); }
    if(!file_exists($filepath)) { file_put_contents($filepath,$started_contents); }
    $get = $_REQUEST;
    $user_ip = $_SERVER['REMOTE_ADDR'];
    $time = time();
    $date = date("d/m/Y H:i:s");
    if(isset($_SERVER['REQUEST_METHOD'])) { $r_method = $_SERVER['REQUEST_METHOD']; }
    $actual_link = "http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
    $words = array('DROP TABLE','DROP DATABASE','drop table','drop database','UPDATE ','update ','INSERT INTO ','insert into ','INSERT ','insert ','SELECT ','select ','SHOW TABLES','show tables','SHOW DATABASES','show databases','USE ','use ','SET ','set ');
    $words = join("|", $words);
    $matches = array();
    foreach($get as $v => $k) {
      if ( preg_match('/' . $words . '/i', $k, $matches) ){
        
        $contents = '----------------------------------------------------------------------';
        $contents .= 'SQL Injection detected!';
        $contents .= 'User IP Address: '.$user_ip.'';
        $contents .= 'Request Method: '.$r_method.'';
        $contents .= 'Request String: '.$v.'';
        $contents .= 'Request Value: '.$k.'';
        $contents .= 'Sent from url: '.$actual_link.'';
        $contents .= 'Date: '.$date.'';      
        $file_contents = file_get_contents($filepath);
        $new_contents = $file_contents.'';
        $new_contents .= $contents;
        file_put_contents($filepath,$new_contents);
      }
    }
    }
  } 
  
  function SQL_DEBUG($value) { 
    if($value == '') return false; 

    $value = str_ireplace( 
      array ( 
        '*', 
        'SELECT ', 
        'UPDATE ', 
        'DELETE ', 
        'INSERT ',
        'TABLE ',
        'DROP ',                  
        'INTO', 
        'VALUES', 
        'FROM', 
        'LEFT', 
        'JOIN', 
        'WHERE', 
        'LIMIT', 
        'ORDER BY', 
        'AND', 
        'OR ',
        'DESC', 
        'ASC', 
        'ON ' 
      ), 
      array ( 
        "&#42; ", 
        "&#x53;ELECT ", 
        "U&#x50;DATE ",
        "DEL&#x45;TE ",
        "IN&#x53;ERT ", 
        "TA&#x42;LE ", 
        "&#x44;ROP ", 
        "I&#x4E;TO ", 
        "VALUE&#x53; ", 
        "&#x46;ROM ", 
        "L&#x45;FT ", 
        "&#x4A;OIN ", 
        "W&#x48;ERE ", 
        "L&#x49;MIT ", 
        "&#x4F;RDER BY ", 
        "A&#x4E;D ", 
        "&#x4F;R ", 
        "DE&#x53;C ", 
        "A&#x53;C ", 
        "&#x4F;N " 
      ), 
    $value 
  ); 

    return $value;
  }
  
  function SHELL_DEBUG($value) {
    if($value == '') return false; 
    
    $value = str_ireplace( 
      array ( 
        'passthru', 
        'exec', 
        'shell_exec', 
        'system',
        'phpinfo'
      ), 
      array ( 
        "pa&#x73;&#x73;thru", 
        "exe&#xE7;", 
        "&#x73;hell_exec",
        "&#x73;ystem",
        "&#x70;hpinfo" 
      ), 
    $value 
  ); 

    return $value;
  }
  
    function secureGET(&$value, $key) {
        $_GET[$key] = htmlspecialchars(stripslashes($_GET[$key]));
        $_GET[$key] = str_ireplace("script", "&#x73;cript", $_GET[$key]);
        $_GET[$key] = mysql_real_escape_string($_GET[$key]);
    $_GET[$key] = $this->SQL_DEBUG($_GET[$key]);
    $_GET[$key] = $this->SHELL_DEBUG($_GET[$key]);
        return $_GET[$key];
    }
    
    function securePOST(&$value, $key) {
        $_POST[$key] = htmlspecialchars(stripslashes($_POST[$key]));
        $_POST[$key] = str_ireplace("script", "&#x73;cript", $_POST[$key]);
        $_POST[$key] = mysql_real_escape_string($_POST[$key]);
    $_POST[$key] = $this->SQL_DEBUG($_POST[$key]);
    $_POST[$key] = $this->SHELL_DEBUG($_POST[$key]);
        return $_POST[$key];
    }
  
  function secureREQUEST(&$value, $key) {
        $_REQUEST[$key] = htmlspecialchars(stripslashes($_REQUEST[$key]));
        $_REQUEST[$key] = str_ireplace("script", "%73cript", $_REQUEST[$key]);
        $_REQUEST[$key] = mysql_real_escape_string($_REQUEST[$key]);
    $_REQUEST[$key] = $this->SQL_DEBUG($_REQUEST[$key]);
    $_REQUEST[$key] = $this->SHELL_DEBUG($_REQUEST[$key]);
        return $_REQUEST[$key];
    }
  
  function secureSESSION(&$value, $key) {
        $_SESSION[$key] = htmlspecialchars(stripslashes($_SESSION[$key]));
        $_SESSION[$key] = str_ireplace("script", "%73cript", $_SESSION[$key]);
        $_SESSION[$key] = mysql_real_escape_string($_SESSION[$key]);
    $_SESSION[$key] = $this->SQL_DEBUG($_SESSION[$key]);
    $_SESSION[$key] = $this->SHELL_DEBUG($_SESSION[$key]);
        return $_SESSION[$key];
    }
  
  function secureCOOKIE(&$value, $key) {
        $_COOKIE[$key] = htmlspecialchars(stripslashes($_COOKIE[$key]));
        $_COOKIE[$key] = str_ireplace("script", "%73cript", $_COOKIE[$key]);
        $_COOKIE[$key] = mysql_real_escape_string($_COOKIE[$key]);
    $_COOKIE[$key] = $this->SQL_DEBUG($_COOKIE[$key]);
    $_COOKIE[$key] = $this->SHELL_DEBUG($_COOKIE[$key]);
        return $_COOKIE[$key];
    }
  
  function secureFILES(&$value, $key) {
        $_FILES[$key] = htmlspecialchars(stripslashes($_FILES[$key]));
        $_FILES[$key] = str_ireplace("script", "%73cript", $_FILES[$key]);
        $_FILES[$key] = mysql_real_escape_string($_FILES[$key]);
    $_FILES[$key] = $this->SQL_DEBUG($_FILES[$key]);
    $_FILES[$key] = $this->SHELL_DEBUG($_FILES[$key]);
        return $_FILES[$key];
    }
        
    function secureGlobals() {
    // if(!error_reporting(0)) {
    //  error_reporting(0);
    // }
        array_walk($_GET, array($this, 'secureGET'));
        array_walk($_POST, array($this, 'securePOST'));
    array_walk($_REQUEST, array($this, 'secureREQUEST'));
    if(isset($_SESSION)) {
    array_walk($_SESSION, array($this, 'secureSESSION'));
    }
    array_walk($_COOKIE, array($this, 'secureCOOKIE'));
    array_walk($_FILES, array($this, 'secureFILES'));
    }
}
?>

