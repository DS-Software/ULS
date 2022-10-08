<?php

	$scope_desc = array(
		'auth' => array(
			"name" => "Проверка Данных",
			"description" => "• Приложение узнает ваш Ключ Доступа Пользователя."
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
		'admin' => array(
			"name" => "Доступ к управлению ULS",
			"description" => "• Приложение сможет управлять ULS!"
		)
	);

	function getScopes($expl_scopes, $infinite=0, $admin_required=false){
		$scopes = array(
			'auth' => true,
			'email' => false,
			'personal' => false,
			'profile_management' => false,
			'admin' => false
		);
		
		if(isset($expl_scopes["personal"])){
			$scopes['personal'] = true;
		}
		if(isset($expl_scopes["email"])){
			$scopes['email'] = true;
		}
		if(isset($expl_scopes["profile_management"]) && $infinite == 1){
			$scopes['profile_management'] = true;
		}
		
		if($admin_required){
			$scopes['admin'] = true;
		}
		
		return $scopes;
	}

	if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) { $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP']; }
	
	$maintenance_mode = false;
	
	$spam_check = true;
	$spam_provider = "https://disposable.debounce.io/?email=";
	
	$captcha_required = true;

	$login_site = "https://example.com/login";
	$status_page = "https://status.example.com/";
	$support = "Either support link or EMail address.";
	
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
	
	$enable_creation = true;
	$int_url = $login_site . "/apps";
	$integrations_limit = 15;
	
	$allowed_admins = []; // [1 => true] ([USER_ID => true])
?>