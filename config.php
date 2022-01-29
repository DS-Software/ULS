<?php
	if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) { $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP']; }
	
	$allowed_origins = array(
		0 => "https://ds-software.xyz",
		1 => "https://alpha.ds-software.xyz",
		2 => "https://gp.ds-software.xyz",
		3 => "https://dev.ds-software.xyz",
		4 => "https://artemdevvk.ml",
		5 => "https://lk.ds-software.xyz"
	);
	
	$maintenance_mode = false;

	$login_site = "https://login.ds-software.xyz";
	
	$domain_name = "/"; /*    / is default  */
	
	$session_length = 32;
	
	/*
		Variables below this point
		are SECURED variables.
	*/
	
	$service_key = ''; 
	
	$encryption_key = "";
	
	$service_oauth = "";
	
	$service_verification = "";
	
	$database = array(
		'login' => '',
		'password' => '',
		'dbname' => '',
		'hostname' => ''
	);

	$email_settings = array(
		'smtp' => '',
		'port' => '',
		'messageFrom' => '',
		'login' => '',
		'password' => ''
	);
	
	$projects = array(
		'chat' => array(
			'url' => "https://ds-software.xyz/chat",
			'api' => "https://ds-software.xyz/chat/api.php",
			'key' => ''
		),
		'alpha_chat' => array(
			'url' => "https://alpha.ds-software.xyz",
			'api' => "https://alpha.ds-software.xyz/api.php",
			'key' => ''
		),
		'gp_chat' => array(
			'url' => "https://gp.ds-software.xyz/chat",
			'api' => "https://gp.ds-software.xyz/chat/api.php",
			'key' => ''
		),
		'license' => array(
			'url' => "https://ds-software.xyz/license",
			'api' => "https://ds-software.xyz/license/api.php",
			'key' => ''
		),
		'dev_chat' => array(
			'url' => "https://dev.ds-software.xyz/",
			'api' => "https://dev.ds-software.xyz/api.php",
			'key' => ''
		)
	);
	
?>