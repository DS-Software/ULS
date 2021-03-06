<?php

	$scope_desc = array(
		'auth' => array(
			"name" => "Проверка Данных",
			"description" => "• Приложение узнает ваш ключ авторизации."
		),
		'email' => array(
			"name" => "Доступ к общей информации",
			"description" => "• Приложение узнает Вашу основную почту."
		),
		'personal' => array(
			"name" => "Доступ к личной информации",
			"description" => "• Приложение получит доступ к Вашей личной информации."
		),
		'profile_management' => array(
			"name" => "Управление Аккаунтом",
			"description" => "• Приложение сможет управлять вашим аккаунтом!"
		),
	);

	function getScopes($scope_text, $infinite=1){
		global $scope_desc;
		$scopes = array_fill_keys(array_keys($scope_desc), false);
		$scopes['auth'] = true;
		
		$expl_scopes = explode(",", $scope_text);
			
		if(in_array("personal", $expl_scopes)){
			$scopes['personal'] = true;
		}
		if(in_array("email", $expl_scopes)){
			$scopes['email'] = true;
		}
		if(in_array("profile_management", $expl_scopes) && $infinite == 1){
			$scopes['profile_management'] = true;
		}
		if(in_array("all", $expl_scopes)){
			$scopes = array_fill_keys(array_keys($scopes), true);
			if($infinite != 1){
				$scopes['profile_management'] = false;
			}
		}
		
		return $scopes;
	}

	if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) { $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP']; }
	
	$maintenance_mode = false;

	$spam_provider = "https://spam.ds-software.xyz/api/?email=";

	$login_site = "https://example.com/login";
	$status_page = "https://status.example.com/";
	
	$domain_name = "/"; /*    / is default  */
	
	$session_length = 32;
	
	$service_key = "Very_Long_Service_Key"
	
	$encryption_key = "Long_Key_For_AES_Encryption.";
	
	$database = array(
		'login' => 'database_login',
		'password' => 'database_password',
		'dbname' => 'database_auth',
		'hostname' => 'localhost'
	);
	
	$email_info = array(
		'$project_name' => "",
		'$main_link' => $login_site,
		'$login_site' => $login_site,
		'$support_email' => "mailto:",
		'$support_email_label' => ""
	);

	$email_settings = array(
		'smtp' => 'your.smtp.provider',
		'port' => '465',
		'messageFrom' => 'Sender Name',
		'login' => 'SMTP Login',
		'password' => 'SMTP Password'
	);
	
?>