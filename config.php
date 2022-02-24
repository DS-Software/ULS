<?php
	if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) { $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP']; }
	
	$maintenance_mode = false;

	$login_site = "https://example.com/login";
	
	$domain_name = "/"; /*    / is default  */
	
	$session_length = 32;
	
	$service_key = "Very_Long_Service_Key";
	
	$encryption_key = "Long_Key_For_AES_Encryption.";
	
	$database = array(
		'login' => 'database_login',
		'password' => 'database_password',
		'dbname' => 'database_auth',
		'hostname' => 'localhost'
	);

	$email_settings = array(
		'smtp' => 'your.smtp.provider',
		'port' => '465',
		'messageFrom' => 'Sender Name',
		'login' => 'SMTP Login',
		'password' => 'SMTP Password'
	);
	
?>