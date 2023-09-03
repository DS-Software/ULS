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

	/*
		If using CAPTCHA (field $captcha_required is true), put the correct values 
		in the field below. For more info - https://dash.cloudflare.com/?to=/:account/turnstile
		
		$turnstile_public is your Site Key.
		$turnstile_private is your Secret Key.
		
		If you aren't using CAPTCHA - set $captcha_required to false and ignore
		the fields below.
	*/
	
	$captcha_required = true;
	$turnstile_public = "";
	$turnstile_private = "";

	$login_site = "https://example.com/login";
	$status_page = "https://status.example.com/";
	$support = "Either support link or EMail address.";
	$support_email = "Either support link or EMail address.";
	$platform_name = "DS Software ULS";
	
	$domain_name = "/"; #  / is default
	
	$session_length = 32;
	
	$service_key = "Very_Long_Service_Key";
	
	$encryption_key = "Long_Key_For_AES_Encryption";

	$enable_webauthn = true;
	$user_verification_requirement = "required";
	/* 
		Types of UV Requirements:
		- required : user must verify, otherwise fail
		- preferred : user verification is preferred, but it won't fail
		- discouraged : user verification should not be used

		Required might break some authenticators that
		cannot verify users.
	*/

	/*
		Relying party ID is the address of your site, for example:
		https://webauthn.example.com/auth relying party will be webauthn.example.com
	*/
	$relying_party_id = "example.com";

	$attestation_formats = array(
		"android-key" => [
			"name" => "Android Key",
			"icon" => "fa-mobile"
		],
		"android-safetynet" => [
			"name" => "Android SafetyNet",
			"icon" => "fa-mobile"
		],
		"apple" => [
			"name" => "Apple Attestation",
			"icon" => "fa-mobile"
		],
		"fido-u2f" => [
			"name" => "FIDO U2F",
			"icon" => "fa-microchip"
		],
		"none" => [
			"name" => "Passkey",
			"icon" => "fa-key"
		],
		"packed" => [
			"name" => "Hardware Key",
			"icon" => "fa-microchip"
		],
		"tpm" => [
			"name" => "TPM Attestation",
			"icon" => "fa-desktop"
		]
	);
	
	$database = array(
		'login' => 'database_login',
		'password' => 'database_password',
		'dbname' => 'database_auth',
		'hostname' => 'localhost'
	);
	
	$email_info = array(
		'$project_name' => $platform_name,
		'$main_link' => $login_site,
		'$login_site' => $login_site,
		'$support_email' => "mailto:{$support_email}",
		'$support_email_label' => $support_email
	);
	
	/*
		Do not use this feature unless you are experiencing severe issues with email delivery. This flag will disable all email verification.
		
		DO NOT USE THIS FEATURE ON A REAL SERVER!
	*/
	$disable_email = false;

	$email_settings = array(
		'smtp' => 'your.smtp.provider',
		'port' => '465',
		'messageFrom' => 'Sender Name',
		'login' => 'SMTP Login',
		'password' => 'SMTP Password',
		'email_debug' => false // Use it when u get EMAIL_DELIVERY_FAULT error.
	);
	
	$enable_creation = true;
	$int_url = $login_site . "/apps";
	
	$allowed_admins = []; // [1 => true] ([USER_ID => true])
?>
