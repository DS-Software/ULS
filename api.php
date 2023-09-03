<?php

require_once 'config.php';
require_once 'database.php';
require_once './libs/webauthn/WebAuthn.php';

session_start();

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

function returnError($message) {
	$error = array(
		'result' => 'FAULT',
		'reason' => $message
	);

	echo json_encode($error, 1);
	die();
}

function isRateExceeded($method, $ip, $max_rate, $expired) {
	$requests = getRequestCount($method, $ip);
	$requests_count = $requests['count'];
	$first_request = $requests['time'];

	if ($requests_count == 0) {
		addRequest($method, $ip);
		return false;
	}
	if (time() > $first_request + $expired) {
		clearRequests($method, $ip);
		addRequest($method, $ip);
		return false;
	}
	if ($requests_count >= $max_rate) {
		if (isset($_COOKIE['passed_captcha'])) {
			global $domain_name;
			global $captcha_required;
			global $turnstile_private;

			if ($captcha_required) {
				$turnstile_token = $_COOKIE['passed_captcha'];
				
				$ip = $_SERVER['REMOTE_ADDR'];
				$url_path = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
				$data = array('secret' => $turnstile_private, 'response' => $turnstile_token, 'remoteip' => $ip);
					
				$options = array(
					'http' => array(
					'method' => 'POST',
					'content' => http_build_query($data))
				);
					
				$stream = stream_context_create($options);
				$result = file_get_contents($url_path, false, $stream);
				   
				$responseKeys = json_decode($result,true);
				
				if($responseKeys['success']){
					return false;
				}
			}
		}
		return true;
	}
	addRequest($method, $ip);
	return false;
}

function getRequestCount($method, $ip) {
	global $login_db;
	return $login_db->getRequests($method, $ip);
}

function addRequest($method, $ip) {
	global $login_db;
	$login_db->addRequest($method, $ip);
}

function clearRequests($method, $ip) {
	global $login_db;
	$login_db->clearRequest($method, $ip);
}

function hasFinishedRegister($user_info) {
	$user_nick = $user_info['user_nick'];
	$user_name = $user_info['user_name'];
	$user_surname = $user_info['user_surname'];
	$birthday = $user_info['birthday'];

	if ($user_nick != '' && strlen($user_nick) >= 3 && 16 >= strlen($user_nick)) {
		if ($user_name != '' && strlen($user_name) >= 2 && 32 >= strlen($user_name)) {
			if ($user_surname != '' && strlen($user_surname) >= 2 && 32 >= strlen($user_surname)) {
				if ($birthday != 0) {
					return true;
				}
			}
		}
	}
	return false;
}

function checkLoggedIn($user_id, $SLID, $email, $session, $user_ip, $user_key, $user_info) {
	global $service_key;

	if ($user_info['user_id'] == $user_id && $user_info['user_id'] != null) {
		if ($user_info['SLID'] == $SLID) {
			if ($user_ip == $_SERVER['REMOTE_ADDR']) {
				$true_hash = hash("sha512", "{$session}_{$email}_{$user_id}_{$SLID}_{$_SERVER['REMOTE_ADDR']}_$service_key");

				if ($true_hash == $user_key) {
					return true;
				}
			}
		}
	}
	return false;
}

function checkDisposableEmail($email) {
	global $spam_provider;
	global $spam_check;
	if (!$spam_check) {
		return false;
	}
	$link = $spam_provider . urlencode($email);
	$curl = curl_init($link);
	curl_setopt($curl, CURLOPT_URL, $link);
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

	$resp = curl_exec($curl);
	curl_close($curl);

	$response = json_decode($resp, true);

	if ($response['disposable'] == "true") {
		return true;
	}
	return false;
}

function getAPIToken() {
	$headers = "";
	if (isset($_SERVER['Authorization'])) {
		$headers = trim($_SERVER["Authorization"]);
	} elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
		$headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
	} elseif (function_exists('apache_request_headers')) {
		$requestHeaders = apache_request_headers();
		$requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
		if (isset($requestHeaders['Authorization'])) {
			$headers = trim($requestHeaders['Authorization']);
		}
	}

	$token_raw = explode(" ", $headers);
	$token = null;
	if ($token_raw[0] == "Bearer") {
		$token = $token_raw[1];
	}

	return $token;
}

function deleteLoginCookies() {
	global $domain_name;

	if (isset($_COOKIE['user_verkey'])) {
		setcookie('user_verkey', '', 0, $domain_name);
	}
	if (isset($_COOKIE['user_ip'])) {
		setcookie('user_ip', '', 0, $domain_name);
	}
	if (isset($_COOKIE['session'])) {
		setcookie('session', '', 0, $domain_name);
	}
	if (isset($_COOKIE['email'])) {
		setcookie('email', '', 0, $domain_name);
	}
	if (isset($_COOKIE['SLID'])) {
		setcookie('SLID', '', 0, $domain_name);
	}
	if (isset($_COOKIE['user_id'])) {
		setcookie('user_id', '', 0, $domain_name);
	}
}

function deleteTOTPCookies() {
	global $domain_name;

	if (isset($_COOKIE['totp_verification'])) {
		setcookie('totp_verification', '', 0, $domain_name);
	}
	if (isset($_COOKIE['totp_timestamp'])) {
		setcookie('totp_timestamp', '', 0, $domain_name);
	}
}

function convBase($num, $base_a, $base_b) {
	return gmp_strval(gmp_init($num, $base_a), $base_b);
}

function uniqidReal($length = 16) {
	$bytes = random_bytes(ceil((($length + 1) / 2)));
	return substr(bin2hex($bytes), 0, $length);
}

if ($maintenance_mode) {
	returnError("MAINTENANCE_MODE");
}

$login_db = new database($database);

if (!$login_db->success) {
	returnError("MAINTENANCE_MODE");
}

$method = $_REQUEST['method'];
$section = strtolower($_REQUEST['section']);

if ($section == "unauth") {
	if ($method == "getAccessToken") {
		$user_id = $_COOKIE['user_id'];
		$SLID = $_COOKIE['SLID'];
		$email = $_COOKIE['email'];
		$session = $_COOKIE['session'];
		$user_ip = $_COOKIE['user_ip'];
		$user_key = $_COOKIE['user_verkey'];
		$ip_verify = $_COOKIE['ip_verify'];
		$totp_timestamp = $_COOKIE['totp_timestamp'];
		$totp_verification = $_COOKIE['totp_verification'];

		$user_info = $login_db->getUserInfo($user_id);

		$verified = checkLoggedIn($user_id, $SLID, $email, $session, $user_ip, $user_key, $user_info);

		if ($verified) {
			if ($ip_verify != hash("sha512", "{$SLID}_{$user_info['user_id']}_{$user_ip}_$service_key")) {
				$return = array(
					'result' => 'OK',
					'description' => 'IPVerificationRequired',
					'token' => null
				);

				echo json_encode($return, 1);
				die();
			}
			if ($user_info['2fa_active'] == 1) {
				if ($totp_timestamp + 2678400 < time()) {
					deleteTOTPCookies();
					$totp_timestamp = null;
					$totp_verification = null;
				}

				$true_totp_ver = hash("sha512", "{$SLID}_{$user_info['2fa_secret']}_{$user_info['user_id']}_{$totp_timestamp}_$service_key");

				if ($true_totp_ver != $totp_verification) {
					$verified = false;
					$return = array(
						'result' => 'OK',
						'description' => '2faVerificationRequired',
						'token' => null
					);

					echo json_encode($return, 1);
					die();
				}
			}

			if ($user_info['is_banned'] == 1 && !$allowed_admins[$user_id]) {
				returnError("ACCOUNT_BANNED");
			}

			$scopes = getScopes(['profile_management' => ''], 1, true);
			$at_seed = bin2hex(random_bytes(32));

			$access_token = array(
				'uls_id' => $user_info['user_id'],
				'seed' => $at_seed,
				'scopes' => $scopes,
				'sign' => hash('sha512', $user_info['user_id'] . "_" . $at_seed . "_" . json_encode($scopes) . "_" . $user_info['api_key_seed'] . "_" . $service_key)
			);

			$access_token = base64_encode(json_encode($access_token));

			if (!hasFinishedRegister($user_info)) {
				$return = array(
					'result' => 'OK',
					'description' => 'unfinishedReg',
					'token' => $access_token
				);

				echo json_encode($return, 1);
				die();
			}

			$return = array(
				'result' => 'OK',
				'token' => $access_token
			);

			echo json_encode($return, 1);
		}
		else{
			deleteLoginCookies();
			returnError("WRONG_LOGIN_INFO");
		}
		die();
	}

	if ($method == "authorize") {
		if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 10, 60)) {
			returnError("RATE_LIMIT_EXCEEDED");
		}
		$login = $_POST['login'];
		$password = $_POST['password'];
		if (checkDisposableEmail($login)) {
			returnError("DISPOSABLE_EMAIL");
		}

		$log_user_id = $login_db->getUIDByEMail($login);
		if (is_int($log_user_id)) {
			$user_info = $login_db->getUserInfo($log_user_id);
			$true_password_hash = $user_info['password_hash'];
			$password_hash = hash("sha512", $password . "_" . $user_info['salt']);
			if ($password_hash != $true_password_hash) {
				returnError('WRONG_CREDENTIALS');
			}
		}
		else{
			returnError('WRONG_CREDENTIALS');
		}

		if ($user_info['is_banned'] == 1 && !$allowed_admins[$log_user_id]) {
			$return = array(
				'result' => 'FAULT',
				'reason' => 'ACCOUNT_BANNED',
				'support' => "$support"
			);
			echo json_encode($return);
			die();
		}

		$needs_email_check = $user_info['email_check'];

		if (($_SERVER['REMOTE_ADDR'] == $user_info['user_ip']) || $needs_email_check == 0 || $disable_email) {
			$rsid = bin2hex(random_bytes($session_length / 2));
			$timestamp = time();
			$session_id = hash('sha256', $rsid . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);

			$ip_verify = hash("sha512", "{$user_info['SLID']}_{$user_info['user_id']}_{$_SERVER['REMOTE_ADDR']}_$service_key");

			setcookie("user_id", $log_user_id, time() + 2678400, $domain_name);
			setcookie("email", $login, time() + 2678400, $domain_name);
			setcookie("user_ip", $_SERVER['REMOTE_ADDR'], time() + 2678400, $domain_name);
			setcookie("user_verkey", hash("sha512", "{$session_id}_{$login}_{$log_user_id}_{$user_info['SLID']}_{$_SERVER['REMOTE_ADDR']}_$service_key"), time() + 2678400, $domain_name);
			setcookie("session", $session_id, time() + 2678400, $domain_name);
			setcookie("SLID", $user_info['SLID'], time() + 2678400, $domain_name);
			setcookie("ip_verify", $ip_verify, time() + 2678400, $domain_name);

			$return = array(
				'result' => 'OK',
				'description' => 'Success'
			);
		}
		else{
			require_once 'libs' . DIRECTORY_SEPARATOR . 'email_templates.php';
			require_once 'libs' . DIRECTORY_SEPARATOR . 'email_handler.php';

			$ip_ver_code = strtoupper(uniqidReal(8));
			$ip_ver_code_hash = hash("sha512", "{$ip_ver_code}_{$user_info['SLID']}_$service_key");
			$login_db->setIPCode($log_user_id, $ip_ver_code_hash);

			$replaceArray = array(
				'$username' => $user_info['user_nick'] == "" ? "Неизвестный Пользователь" : $user_info['user_nick'],
				'$code' => $ip_ver_code,
				'$ip' => $_SERVER['REMOTE_ADDR']
			);

			$replaceArray = array_merge($replaceArray, $email_info);

			$email_html = strtr($NewIPEmail, $replaceArray);
			$subject = strtr($messageNewIPSubject, $replaceArray);

			send_email($email_settings, $login, $email_html, $subject);

			$rsid = bin2hex(random_bytes($session_length / 2));
			$timestamp = time();
			$session_id = hash('sha256', $rsid . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);

			setcookie("user_id", $log_user_id, time() + 2678400, $domain_name);
			setcookie("email", $login, time() + 2678400, $domain_name);
			setcookie("user_ip", $_SERVER['REMOTE_ADDR'], time() + 2678400, $domain_name);
			setcookie("user_verkey", hash("sha512", "{$session_id}_{$login}_{$log_user_id}_{$user_info['SLID']}_{$_SERVER['REMOTE_ADDR']}_$service_key"), time() + 2678400, $domain_name);
			setcookie("session", $session_id, time() + 2678400, $domain_name);
			setcookie("SLID", $user_info['SLID'], time() + 2678400, $domain_name);

			$return = array(
				'result' => 'OK',
				'description' => 'emailVerificationRequired'
			);
		}
		echo json_encode($return);
		die();
	}
	
	if ($method == "sendIPCode") {
		if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 1, 300)) {
			returnError("RATE_LIMIT_EXCEEDED");
		}
		
		$user_id = $_COOKIE['user_id'];
		$SLID = $_COOKIE['SLID'];
		$email = $_COOKIE['email'];
		$session = $_COOKIE['session'];
		$user_ip = $_COOKIE['user_ip'];
		$user_key = $_COOKIE['user_verkey'];

		$user_info = $login_db->getUserInfo($user_id);

		$verified = checkLoggedIn($user_id, $SLID, $email, $session, $user_ip, $user_key, $user_info);

		if ($verified) {
			if ($user_info['is_banned'] == 1 && !$allowed_admins[$user_id]) {
				$return = array(
					'result' => 'FAULT',
					'reason' => 'ACCOUNT_BANNED',
					'support' => "$support"
				);
				echo json_encode($return);
				die();
			}
			
			if($user_info['email_check'] != 0){
				require_once 'libs' . DIRECTORY_SEPARATOR . 'email_templates.php';
				require_once 'libs' . DIRECTORY_SEPARATOR . 'email_handler.php';

				$ip_ver_code = strtoupper(uniqidReal(8));
				$ip_ver_code_hash = hash("sha512", "{$ip_ver_code}_{$user_info['SLID']}_$service_key");
				$login_db->setIPCode($user_id, $ip_ver_code_hash);

				$replaceArray = array(
					'$username' => $user_info['user_nick'] == "" ? "Неизвестный Пользователь" : $user_info['user_nick'],
					'$code' => $ip_ver_code,
					'$ip' => $_SERVER['REMOTE_ADDR']
				);

				$replaceArray = array_merge($replaceArray, $email_info);

				$email_html = strtr($NewIPEmail, $replaceArray);
				$subject = strtr($messageNewIPSubject, $replaceArray);

				send_email($email_settings, $user_info['user_email'], $email_html, $subject);
			}
			
			$return = array(
				'result' => 'OK',
				'description' => 'Success'
			);
			echo json_encode($return);
			die();
		}
		returnError("WRONG_CREDENTIALS");
	}

	if ($method == 'verifyIP') {
		if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 10, 60)) {
			returnError("RATE_LIMIT_EXCEEDED");
		}
		$user_id = $_COOKIE['user_id'];
		$SLID = $_COOKIE['SLID'];
		$email = $_COOKIE['email'];
		$session = $_COOKIE['session'];
		$user_ip = $_COOKIE['user_ip'];
		$user_key = $_COOKIE['user_verkey'];
		$code = strtoupper($_REQUEST['code']);

		$user_info = $login_db->getUserInfo($user_id);

		$verified = checkLoggedIn($user_id, $SLID, $email, $session, $user_ip, $user_key, $user_info);

		if ($verified) {
			if ($user_info['user_id'] == $user_id && $user_id != "") {
				$true_code_hash = $user_info['ip_ver_code'];
				
				$new_code_hash = hash("sha512", "{$code}_{$user_info['SLID']}_$service_key");

				if ($true_code_hash == $new_code_hash) {
					$ip_verify = hash("sha512", "{$user_info['SLID']}_{$user_info['user_id']}_{$_SERVER['REMOTE_ADDR']}_$service_key");

					setcookie("ip_verify", $ip_verify, time() + 2678400, $domain_name);
					$login_db->setUserIP($user_id, $_SERVER['REMOTE_ADDR']);
					$login_db->clearIPCode($user_id);

					$return = array(
						'result' => 'OK',
						'description' => 'Success'
					);

					echo json_encode($return);
					die();
				}
				else{
					returnError("WRONG_VER_CODE");
				}
			}
		}
		returnError("WRONG_LOGIN_INFO");
	}

	if ($method == 'sendRegisterMessage') {
		if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 1, 300)) {
			returnError("RATE_LIMIT_EXCEEDED");
		}
		$login = $_REQUEST['login'];

		if (checkDisposableEmail($login)) {
			returnError("DISPOSABLE_EMAIL");
		}

		if (!filter_var($login, FILTER_VALIDATE_EMAIL)) {
			returnError("INVALID_EMAIL");
		}
		$password = $_REQUEST['password'];

		if (!$login_db->wasEmailRegistered($login)) {
			require_once 'libs' . DIRECTORY_SEPARATOR . 'encryption.php';
			require_once 'libs' . DIRECTORY_SEPARATOR . 'email_templates.php';
			require_once 'libs' . DIRECTORY_SEPARATOR . 'email_handler.php';

			$timestamp = time();
			$rsid = bin2hex(random_bytes($session_length / 2));
			$session_id = hash('sha256', $rsid . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);
			$encrypted_password_hash = safe_encrypt($password, $encryption_key);
			setcookie("register_password", $encrypted_password_hash, $timestamp + 900, $domain_name);
			setcookie("register_verify", hash("sha256", $encrypted_password_hash . "_" . $service_key . "_" . $session_id), $timestamp + 900, $domain_name);

			$email_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $password . '_' . $timestamp . "_" . $session_id);

			$auth_link = $login_site . "/auth_manager.php?method=registerNewUser&timestamp=$timestamp&login=$login&email_ver_id=$email_ver_id&session_id=$session_id&rand_session_id=$rsid";

			$replaceArray = array(
				'$username' => "",
				'$link' => $auth_link,
				'$ip' => $_SERVER['REMOTE_ADDR']
			);

			$replaceArray = array_merge($replaceArray, $email_info);

			$email_html = strtr($registerEmail, $replaceArray);
			$subject = strtr($messageRegisterSubject, $replaceArray);

			send_email($email_settings, $login, $email_html, $subject);

		}
		$return = array(
			'result' => 'OK',
			'description' => 'emailVerificationRequired'
		);
		echo json_encode($return);
		die();
	}

	if ($method == "registerNewUser") {
		if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 1, 300)) {
			returnError("RATE_LIMIT_EXCEEDED");
		}

		$login = $_REQUEST['login'];
		if (checkDisposableEmail($login)) {
			returnError("DISPOSABLE_EMAIL");
		}

		$timestamp = $_REQUEST['timestamp'];
		$email_ver_id = $_REQUEST['email_ver_id'];
		$session_id = $_REQUEST['session_id'];
		$rand_session_id = $_REQUEST['rand_session_id'];
		$password_hash = $_COOKIE['register_password'];
		$register_verify = $_COOKIE['register_verify'];

		if ($timestamp + 900 < time()) {
			returnError("UNABLE_TO_CREATE_ACCOUNT");
		}
		if ($login_db->wasEmailRegistered($login)) {
			returnError("UNABLE_TO_CREATE_ACCOUNT");
		}

		$true_session_id = hash('sha256', $rand_session_id . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);
		if ($true_session_id != $session_id) {
			returnError("UNABLE_TO_CREATE_ACCOUNT");
		}

		$true_register_verify = hash("sha256", $password_hash . "_" . $service_key . "_" . $session_id);
		if ($true_register_verify != $register_verify) {
			returnError("UNABLE_TO_CREATE_ACCOUNT");
		}

		require_once 'libs' . DIRECTORY_SEPARATOR . 'encryption.php';

		$real_password = safe_decrypt($password_hash, $encryption_key);
		if ($real_password === False) {
			returnError("UNABLE_TO_CREATE_ACCOUNT");
		}

		$true_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $real_password . '_' . $timestamp . "_" . $session_id);

		if ($true_ver_id != $email_ver_id) {
			returnError("UNABLE_TO_CREATE_ACCOUNT");
		}

		$salt = hash("sha256", uniqidReal(256));
		$final_password_hash = hash("sha512", $real_password . "_" . $salt);
		$user_id = $login_db->createNewUser($login, $final_password_hash);
		$login_db->setUserIP($user_id, $_SERVER['REMOTE_ADDR']);
		$login_db->regenerateSLID($user_id);
		$login_db->regenerateAPIKey($user_id);
		$login_db->setUserSalt($user_id, $salt);
		$user_info = $login_db->getUserInfo($user_id);

		setcookie('register_password', '', 0, '/');
		setcookie('register_verify', '', 0, '/');

		setcookie("user_id", $user_id, time() + 2678400, $domain_name);
		setcookie("email", $login, time() + 2678400, $domain_name);
		setcookie("user_ip", $_SERVER['REMOTE_ADDR'], time() + 2678400, $domain_name);
		setcookie("user_verkey", hash("sha512", "{$session_id}_{$login}_{$user_id}_{$user_info['SLID']}_{$_SERVER['REMOTE_ADDR']}_$service_key"), time() + 2678400, $domain_name);
		setcookie("session", $session_id, time() + 2678400, $domain_name);
		setcookie("SLID", $user_info['SLID'], time() + 2678400, $domain_name);

		$ip_verify = hash("sha512", "{$user_info['SLID']}_{$user_id}_{$_SERVER['REMOTE_ADDR']}_$service_key");

		setcookie("ip_verify", $ip_verify, time() + 2678400, $domain_name);
		$login_db->setUserIP($user_id, $_SERVER['REMOTE_ADDR']);

		$return = array(
			'result' => 'OK',
			'description' => 'Success'
		);

		echo json_encode($return);
		die();
	}

	if ($method == 'sendRestoreEmail') {
		if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 1, 300)) {
			returnError("RATE_LIMIT_EXCEEDED");
		}
		$login = $_REQUEST['login'];
		if (!filter_var($login, FILTER_VALIDATE_EMAIL)) {
			returnError("INVALID_EMAIL");
		}
		if (checkDisposableEmail($login)) {
			returnError("DISPOSABLE_EMAIL");
		}

		if ($login_db->wasEmailRegistered($login)) {
			require_once 'libs' . DIRECTORY_SEPARATOR . 'email_templates.php';
			require_once 'libs' . DIRECTORY_SEPARATOR . 'email_handler.php';

			$timestamp = time();
			$rsid = bin2hex(random_bytes($session_length / 2));
			$session_id = hash('sha256', $rsid . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);

			$log_user_id = $login_db->getUIDByEMail($login);
			$user_info = $login_db->getUserInfo($log_user_id);
			$email_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $timestamp . "_" . $user_info['SLID'] . "_" . $session_id);

			$auth_link = $login_site . "/auth_manager.php?method=restorePassword&timestamp=$timestamp&login=$login&email_ver_id=$email_ver_id&rand_session_id=$rsid&session_id=$session_id";

			$replaceArray = array(
				'$username' => $user_info['user_nick'] == "" ? "Неизвестный Пользователь" : $user_info['user_nick'],
				'$link' => $auth_link,
				'$ip' => $_SERVER['REMOTE_ADDR']
			);

			$replaceArray = array_merge($replaceArray, $email_info);

			$email_html = strtr($restorePasswordEmail, $replaceArray);
			$subject = strtr($messageRestoreSubject, $replaceArray);

			send_email($email_settings, $login, $email_html, $subject);

			$login_db->setLastSID($log_user_id, $session_id);

		}
		$return = array(
			'result' => 'OK',
			'description' => 'emailVerificationRequired'
		);
		echo json_encode($return);
		die();
	}

	if ($method == "restorePassword") {
		if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 1, 300)) {
			returnError("RATE_LIMIT_EXCEEDED");
		}
		$login = $_REQUEST['login'];
		if (checkDisposableEmail($login)) {
			returnError("DISPOSABLE_EMAIL");
		}

		$timestamp = $_REQUEST['timestamp'];
		$email_ver_id = $_REQUEST['email_ver_id'];
		$session_id = $_REQUEST['session_id'];
		$rand_session_id = $_REQUEST['rand_session_id'];
		$new_password = $_COOKIE['restore_password'];

		if (!isset($new_password)) {
			returnError("PASSWORD_IS_MISSING");
		}

		$log_user_id = $login_db->getUIDByEMail($login);
		$user_info = $login_db->getUserInfo($log_user_id);

		$true_session_id = hash('sha256', $rand_session_id . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);
		$true_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $timestamp . "_" . $user_info['SLID'] . "_" . $session_id);
		$last_sid = $user_info['last_sid'];

		if ($true_ver_id != $email_ver_id) {
			returnError("UNABLE_TO_CHANGE_PASSWORD");
		}
		if ($timestamp + 900 < time()) {
			returnError("UNABLE_TO_CHANGE_PASSWORD");
		}
		if ($session_id != $true_session_id) {
			returnError("UNABLE_TO_CHANGE_PASSWORD");
		}
		if ($last_sid != $session_id) {
			returnError("UNABLE_TO_CHANGE_PASSWORD");
		}
		if (!$login_db->wasEmailRegistered($login)) {
			returnError("UNABLE_TO_CHANGE_PASSWORD");
		}

		$salt = hash("sha256", uniqidReal(256));
		$final_password_hash = hash("sha512", $new_password . "_" . $salt);

		$login_db->setUserSalt($user_info['user_id'], $salt);
		$login_db->changeUserPassword($user_info['user_id'], $final_password_hash);

		setcookie('restore_password', '', 0, '/');
		$login_db->clearLastSID($log_user_id);

		setcookie("user_id", $log_user_id, time() + 2678400, $domain_name);
		setcookie("email", $login, time() + 2678400, $domain_name);
		setcookie("user_ip", $_SERVER['REMOTE_ADDR'], time() + 2678400, $domain_name);
		setcookie("user_verkey", hash("sha512", "{$session_id}_{$login}_{$log_user_id}_{$user_info['SLID']}_{$_SERVER['REMOTE_ADDR']}_$service_key"), time() + 2678400, $domain_name);
		setcookie("session", $session_id, time() + 2678400, $domain_name);
		setcookie("SLID", $user_info['SLID'], time() + 2678400, $domain_name);

		$ip_verify = hash("sha512", "{$user_info['SLID']}_{$log_user_id}_{$_SERVER['REMOTE_ADDR']}_$service_key");
		setcookie("ip_verify", $ip_verify, time() + 2678400, $domain_name);

		$return = array(
			'result' => 'OK',
			'description' => 'Success'
		);

		echo json_encode($return);
		die();
	}

	if ($method == "changeUserEMail") {
		if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 1, 300)) {
			returnError("RATE_LIMIT_EXCEEDED");
		}
		$new_mail = $_REQUEST['new_mail'];
		if (checkDisposableEmail($new_mail)) {
			returnError("DISPOSABLE_EMAIL");
		}

		$timestamp = $_REQUEST['timestamp'];
		$user_id = $_REQUEST['user_id'];
		$email_ver_id = $_REQUEST['email_ver_id'];
		$session_id = $_REQUEST['session_id'];
		$rand_session_id = $_REQUEST['rand_session_id'];

		$user_info = $login_db->getUserInfo($user_id);

		$true_session_id = hash('sha256', $rand_session_id . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);
		$true_ver_id = hash("sha256", $user_id . '_' . $service_key . '_' . $timestamp . "_" . $user_info['SLID'] . "_" . $session_id . "_" . $new_mail);
		$last_sid = $user_info['last_sid'];

		if ($true_ver_id != $email_ver_id) {
			returnError("UNABLE_TO_CHANGE_EMAIL");
		}
		if ($timestamp + 900 < time()) {
			returnError("UNABLE_TO_CHANGE_EMAIL");
		}
		if ($session_id != $true_session_id) {
			returnError("UNABLE_TO_CHANGE_EMAIL");
		}
		if ($last_sid != $session_id) {
			returnError("UNABLE_TO_CHANGE_EMAIL");
		}
		if ($login_db->wasEmailRegistered($new_mail)) {
			returnError("UNABLE_TO_CHANGE_EMAIL");
		}

		$login_db->changeUserEmail($user_id, $new_mail);
		$login_db->clearLastSID($user_id);

		$return = array(
			'result' => 'OK',
			'description' => 'Success'
		);

		echo json_encode($return);
		die();
	}

	if ($method == "checkTOTP") {
		if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 30, 60)) {
			returnError("RATE_LIMIT_EXCEEDED");
		}
		$otp = $_REQUEST['otp'];
		if ($otp == "") {
			returnError("WRONG_2FA_CODE");
		}

		require_once 'libs' . DIRECTORY_SEPARATOR . "2fa_utils.php";

		$user_id = $_COOKIE['user_id'];
		$SLID = $_COOKIE['SLID'];
		$email = $_COOKIE['email'];
		$session = $_COOKIE['session'];
		$user_ip = $_COOKIE['user_ip'];
		$user_key = $_COOKIE['user_verkey'];

		$user_info = $login_db->getUserInfo($user_id);

		$verified = checkLoggedIn($user_id, $SLID, $email, $session, $user_ip, $user_key, $user_info);

		if ($user_info['2fa_active'] != 1) {
			returnError("2FA_IS_NOT_ENABLED");
		}

		if ($verified) {
			if ($user_info['user_id'] == $user_id && $user_id != "") {
				$totp_instance = TOTPInstance();
				$base32 = Base32Instance();

				$secret = $user_info['2fa_secret'];
				$secret = $base32->decode($secret);

				$key = $totp_instance->GenerateToken($secret);

				if ($otp == $key) {
					$totp_timestamp = time();
					$true_totp_ver = hash("sha512", "{$SLID}_{$user_info['2fa_secret']}_{$user_info['user_id']}_{$totp_timestamp}_$service_key");

					setcookie("totp_timestamp", $totp_timestamp, time() + 2678400, $domain_name);
					setcookie("totp_verification", $true_totp_ver, time() + 2678400, $domain_name);

					$return = array(
						'result' => 'OK',
						'description' => 'Success'
					);

					echo json_encode($return);
					die();
				}
				else{
					returnError("WRONG_2FA_CODE");
				}
			}
		}
		returnError("WRONG_LOGIN_INFO");
	}

	if ($method == "disableTOTP") {
		if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 5, 60)) {
			returnError("RATE_LIMIT_EXCEEDED");
		}

		$user_id = $_COOKIE['user_id'];
		$SLID = $_COOKIE['SLID'];
		$email = $_COOKIE['email'];
		$session = $_COOKIE['session'];
		$user_ip = $_COOKIE['user_ip'];
		$user_key = $_COOKIE['user_verkey'];
		$key = $_REQUEST['key'];

		$user_info = $login_db->getUserInfo($user_id);

		$verified = checkLoggedIn($user_id, $SLID, $email, $session, $user_ip, $user_key, $user_info);

		if ($user_info['2fa_active'] != 1) {
			returnError("2FA_IS_NOT_ENABLED");
		}

		if ($verified) {
			if ($user_info['user_id'] == $user_id && $user_id != "") {
				$hash_code = hash('sha256', $key . "_" . $user_id);
				if ($hash_code == $user_info['2fa_disable_code']) {
					$login_db->setTOTPState($user_id, 0);
					$return = array(
						'result' => "OK",
						'description' => "Success"
					);

					echo json_encode($return);
					die();
				}
				else{
					returnError("WRONG_DISABLE_KEY");
				}
			}
		}

		returnError("WRONG_LOGIN_INFO");
	}

	if ($method == "getWebauthnSession") {
		try{
			$WebAuthn = new lbuchs\WebAuthn\WebAuthn($platform_name, $relying_party_id, null);
			$getArgs = $WebAuthn->getGetArgs([], 300, true, true, true, true, true, $user_verification_requirement === "required");

			$_SESSION['challenge'] = $WebAuthn->getChallenge();

			$return = array(
				'result' => 'OK',
				'description' => 'WAITING_INTERACTION',
				'args' => $getArgs
			);

			echo json_encode($return);
			die();
		}
		catch(Exception $e){
			returnError("FAILED_TO_AUTHENTICATE");
		}
	}

	if ($method == "verifyWebauthnSession") {
		try{
			$WebAuthn = new lbuchs\WebAuthn\WebAuthn($platform_name, $relying_party_id, null);
			$post = trim(file_get_contents('php://input'));
			if ($post) {
				$post = json_decode($post);
			}
			
			$clientDataJSON = base64_decode($post->clientDataJSON);
			$authenticatorData = base64_decode($post->authenticatorData);
			$signature = base64_decode($post->signature);
			$userHandle = base64_decode($post->userHandle);
			$id = base64_decode($post->id);
			$challenge = $_SESSION['challenge'] ?? '';
			$credentialPublicKey = null;

			$passkey_info = $login_db->getPKByCredentials(base64_encode($id));
			if($passkey_info === false){
				returnError("FAILED_TO_AUTHENTICATE");
			}

			$final_key = json_decode($passkey_info['final_key']);

			$credentialPublicKey = $final_key->credentialPublicKey;

			if ($credentialPublicKey === null) {
				returnError("FAILED_TO_AUTHENTICATE");
			}

			if ($userHandle !== hex2bin($final_key->userId) && $userHandle != null) {
				returnError("FAILED_TO_AUTHENTICATE");
			}

			$WebAuthn->processGet($clientDataJSON, $authenticatorData, $signature, $credentialPublicKey, $challenge, null, $user_verification_requirement === "required");

			$user_info = $login_db->getUserInfo($passkey_info['owner_id']);
			if($user_info['user_id'] != $passkey_info['owner_id']){
				returnError("FAILED_TO_AUTHENTICATE");
			}

			$rsid = bin2hex(random_bytes($session_length / 2));
			$timestamp = time();

			$login_db->setUserIP($user_info['user_id'], $_SERVER['REMOTE_ADDR']);

			setcookie("user_id", $user_info['user_id'], time() + 2678400, $domain_name);
			setcookie("email", $user_info['user_email'], time() + 2678400, $domain_name);
			setcookie("user_ip", $_SERVER['REMOTE_ADDR'], time() + 2678400, $domain_name);
			setcookie("user_verkey", hash("sha512", "{$rsid}_{$user_info['user_email']}_{$user_info['user_id']}_{$user_info['SLID']}_{$_SERVER['REMOTE_ADDR']}_$service_key"), time() + 2678400, $domain_name);
			setcookie("session", $rsid, time() + 2678400, $domain_name);
			setcookie("SLID", $user_info['SLID'], time() + 2678400, $domain_name);

			$ip_verify = hash("sha512", "{$user_info['SLID']}_{$user_info['user_id']}_{$_SERVER['REMOTE_ADDR']}_$service_key");
			setcookie("ip_verify", $ip_verify, time() + 2678400, $domain_name);

			if ($user_info['2fa_active'] == 1) {
				$totp_timestamp = time();
				$true_totp_ver = hash("sha512", "{$user_info['SLID']}_{$user_info['2fa_secret']}_{$user_info['user_id']}_{$totp_timestamp}_$service_key");

				setcookie("totp_timestamp", $totp_timestamp, time() + 2678400, $domain_name);
				setcookie("totp_verification", $true_totp_ver, time() + 2678400, $domain_name);
			}

			$return = array(
				'result' => "OK",
				'desc' => "AUTHENTICATED"
			);
			echo json_encode($return);
			die();
		}
		catch(Exception $e){
			returnError("FAILED_TO_AUTHENTICATE");
		}
	}
}
else{
	$access_token = getAPIToken();
	$token_decoded = json_decode(base64_decode($access_token), true);
	$user_id = $token_decoded['uls_id'];
	$token_seed = $token_decoded['seed'];
	$token_scopes = $token_decoded['scopes'];
	$token_sign = $token_decoded['sign'];

	$uinfo = $login_db->getUserInfo($user_id);

	if ($uinfo['user_id'] == null || $uinfo['user_id'] != $user_id) {
		returnError("ACCESS_TOKEN_IS_NOT_VALID");
	}
	$test_sign = hash('sha512', $user_id . "_" . $token_seed . "_" . json_encode($token_scopes) . "_" . $uinfo['api_key_seed'] . "_" . $service_key);

	if ($test_sign != $token_sign) {
		returnError("ACCESS_TOKEN_IS_NOT_VALID");
	}

	if (!hasFinishedRegister($uinfo) && $section != "register") {
		returnError("UNFINISHED_REG");
	}

	if ($uinfo['is_banned'] == 1 && !$allowed_admins[$user_id]) {
		returnError("ACCOUNT_BANNED");
	}

	if ($section == "projects" && $token_scopes['profile_management']) {
		if ($method == "getScopes") {
			$return = array(
				'result' => "OK",
				'scopes' => $scope_desc
			);
			echo json_encode($return);
			die();
		}
		if ($method == "login") {
			if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 10, 60)) {
				returnError("RATE_LIMIT_EXCEEDED");
			}

			$project_public = $_REQUEST['public'];
			$project = $login_db->getLoginProjectInfo($project_public);

			$scopes = getScopes($_REQUEST['scopes'], $project['verified']);

			if ($project['project_id'] == "") {
				returnError("UNKNOWN_PROJECT");
			}

			$timestamp = time();
			$session = hash('sha256', $uinfo['user_id'] . "_" . $project['secret_key'] . "_" . bin2hex(random_bytes(32)) . "_" . $timestamp);

			$at_seed = bin2hex(random_bytes(32));

			$access_token = array(
				'uls_id' => $uinfo['user_id'],
				'seed' => $at_seed,
				'scopes' => $scopes,
				'sign' => hash('sha512', $uinfo['user_id'] . "_" . $at_seed . "_" . json_encode($scopes) . "_" . $uinfo['api_key_seed'] . "_" . $service_key)
			);

			$access_token = base64_encode(json_encode($access_token));

			$user_info = array(
				'user_nick' => $uinfo['user_nick'],
				'verified' => $uinfo['verified'],
				'user_ip' => $_SERVER['REMOTE_ADDR']
			);

			if ($scopes["personal"]) {
				$user_info['user_name'] = $uinfo['user_name'];
				$user_info['user_surname'] = $uinfo['user_surname'];
				$user_info['birthday'] = $uinfo['birthday'];
			}

			if ($scopes["email"]) {
				$user_info['user_email'] = $uinfo['user_email'];
			}

			$user_info = base64_encode(json_encode($user_info));

			$params = "?";
			if (strpos($project['redirect_uri'], "?") !== false) {
				$params = "&";
			}

			$sign = hash('sha512', $uinfo['user_id'] . "_" . $timestamp . "_" . $session . "_" . $access_token . "_" . $user_info . "_" . $project['secret_key']);

			$request_params = array(
				'uls_id' => $uinfo['user_id'],
				'timestamp' => $timestamp,
				'session' => $session,
				'token' => $access_token,
				'user_info' => $user_info,
				'sign' => $sign
			);

			$params .= http_build_query($request_params);

			$redirect_url = $project['redirect_uri'] . $params;

			$return = array(
				'result' => "OK",
				'redirect' => $redirect_url
			);
			echo json_encode($return);
			die();
		}

		if ($method == "getProjectInfo") {
			$project_public = $_REQUEST['public'];
			$onFault = $_REQUEST['onFault'];
			$sign = $_REQUEST['sign'];
			$project = $login_db->getLoginProjectInfo($project_public);

			$fault_redirect = "MALFORMED";

			if (!$project["exists"]) {
				returnError("UNKNOWN_PROJECT");
			}
			if (hash("sha256", $onFault . $project["secret_key"]) == $sign) {
				$fault_redirect = $onFault;
			}
			$return = array(
				'result' => "OK",
				'project_id' => $project['project_id'],
				'project_name' => $project['project_name'],
				'verified' => $project['verified'],
				'fault_redirect' => $fault_redirect
			);
			echo json_encode($return);
			die();
		}
	}
	if ($section == "users" && $token_scopes['profile_management']) {
		if ($method == "getUserInfo") {
			$is_admin = false;
			if ($allowed_admins[$uinfo['user_id']]) {
				$is_admin = true;
			}
			$return = array(
				'result' => "OK",
				'email' => $uinfo['user_email'],
				'user_nick' => $uinfo['user_nick'],
				'user_name' => $uinfo['user_name'],
				'user_surname' => $uinfo['user_surname'],
				'user_bday' => $uinfo['birthday'],
				'verified' => $uinfo['verified'],
				'admin' => $is_admin
			);

			echo json_encode($return);
			die();
		}

		if ($method == "enableEMailCheck") {
			if ($uinfo['email_check'] == 0) {
				$login_db->setEMailCheckState($user_id, 1);

				$return = array(
					'result' => "OK",
					'description' => "Success"
				);
				echo json_encode($return);
				die();
			}
			else{
				returnError("EMAIL_CHECK_WAS_ALREADY_ENABLED");
			}
		}

		if ($method == "disableEMailCheck") {
			if ($uinfo['email_check'] == 1) {
				$login_db->setEMailCheckState($user_id, 0);

				$return = array(
					'result' => "OK",
					'description' => "Success"
				);
				echo json_encode($return);
				die();
			}
			else{
				returnError("EMAIL_CHECK_WAS_NOT_ENABLED");
			}
		}

		if ($method == "regenerateAPIKey") {
			$login_db->regenerateAPIKey($user_id);

			$return = array(
				'result' => "OK",
				'description' => "Success"
			);
			echo json_encode($return);
			die();
		}

		if ($method == "regenerateSLID") {
			$login_db->regenerateSLID($user_id);

			$return = array(
				'result' => "OK",
				'description' => "Success"
			);
			echo json_encode($return);
			die();
		}

		if ($method == "changeUserPassword") {
			$old_password = $_COOKIE['new_password_current'];
			$new_password = $_COOKIE['new_password_new'];

			$old_hash = hash("sha512", $old_password . "_" . $uinfo['salt']);

			if ($uinfo['password_hash'] == $old_hash && $old_password != "") {
				$salt = hash("sha256", uniqidReal(256));
				$new_hash = hash("sha512", $new_password . "_" . $salt);

				$login_db->setUserSalt($user_id, $salt);
				$login_db->changeUserPassword($user_id, $new_hash);

				setcookie('new_password_current', '', 0, $domain_name);
				setcookie('new_password_new', '', 0, $domain_name);

				$return = array(
					'result' => "OK",
					"description" => "Success"
				);
				echo json_encode($return);
				die();
			}
			else{
				returnError("WRONG_PASSWORD");
			}
		}

		if ($method == "changeUserEmail") {
			$login = $uinfo['user_email'];
			$new_email = $_REQUEST['email'];

			if (checkDisposableEmail($new_email)) {
				returnError("DISPOSABLE_EMAIL");
			}

			if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 1, 300)) {
				returnError("RATE_LIMIT_EXCEEDED");
			}

			if ($new_email == $uinfo['user_email']) {
				returnError("YOU_ARE_CURRENTLY_USING_THIS_EMAIL");
			}
			if (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
				returnError("INVALID_EMAIL");
			}
			if (!$login_db->wasEmailRegistered($new_email)) {
				require_once 'libs' . DIRECTORY_SEPARATOR . 'email_templates.php';
				require_once 'libs' . DIRECTORY_SEPARATOR . 'email_handler.php';

				$timestamp = time();
				$rsid = bin2hex(random_bytes($session_length / 2));
				$session_id = hash('sha256', $rsid . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);

				$email_ver_id = hash("sha256", $user_id . '_' . $service_key . '_' . $timestamp . "_" . $uinfo['SLID'] . "_" . $session_id . "_" . $new_email);

				$auth_link = $login_site . "/auth_manager.php?method=changeEMail&timestamp=$timestamp&user_id=$user_id&email_ver_id=$email_ver_id&rand_session_id=$rsid&session_id=$session_id&new_email=$new_email";

				$replaceArray = array(
					'$username' => $uinfo['user_nick'] == "" ? "Неизвестный Пользователь" : $uinfo['user_nick'],
					'$link' => $auth_link,
					'$ip' => $_SERVER['REMOTE_ADDR'],
					'$new_email' => $new_email
				);

				$replaceArray = array_merge($replaceArray, $email_info);

				$email_html = strtr($changeEMail, $replaceArray);
				$subject = strtr($messageChangeEMailSubject, $replaceArray);

				send_email($email_settings, $login, $email_html, $subject);

				$login_db->setLastSID($user_id, $session_id);
			}

			$return = array(
				'result' => 'OK',
				'description' => 'emailVerificationRequired'
			);

			echo json_encode($return);
			die();
		}
	}

	if ($section == "security" && $token_scopes['profile_management']) {
		if ($method == "getSecurityInfo") {
			$return = array(
				'result' => "OK",
				'totp' => $uinfo['2fa_active'],
				'email_check' => $uinfo['email_check']
			);

			echo json_encode($return);
			die();
		}
	}

	if ($section == "totp" && $token_scopes['profile_management']) {
		if ($method == "prepareEnable") {
			if ($uinfo['2fa_active'] == 0) {
				if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 15, 60)) {
					returnError("RATE_LIMIT_EXCEEDED");
				}

				require_once 'libs' . DIRECTORY_SEPARATOR . "2fa_utils.php";

				$first_name = $email_info['$project_name'];
				$email = $uinfo['user_email'];

				$totp_instance = TOTPInstance();
				$base32 = Base32Instance();

				$secret = $totp_instance->GenerateSecret(16);
				$true_secret = $base32->encode($secret);

				$login_db->setTOTPSecret($user_id, $true_secret);

				$totp_url = "libs/gen_2fa_qr.php?fn=$first_name&email=$email&secret=$true_secret";

				$return = array(
					'result' => "OK",
					'url' => $totp_url,
					'secret' => $true_secret
				);
				echo json_encode($return);
				die();
			}
			else{
				returnError("TOTP_WAS_ENABLED_BEFORE");
			}
		}
		if ($method == "enable") {
			if ($uinfo['2fa_active'] == 0) {
				if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 10, 60)) {
					returnError("RATE_LIMIT_EXCEEDED");
				}
				require_once 'libs' . DIRECTORY_SEPARATOR . "2fa_utils.php";

				$otp = $_REQUEST['otp'];
				$totp_instance = TOTPInstance();
				$base32 = Base32Instance();

				$secret = $uinfo['2fa_secret'];
				$secret = $base32->decode($secret);

				$key = $totp_instance->GenerateToken($secret);

				if ($key == $otp) {
					$dis_code = convBase(uniqidReal(20), 16, 36);

					$login_db->setTOTPState($user_id, 1);
					$login_db->setTOTPDisableCode($user_id, $dis_code);

					$return = array(
						'result' => "OK",
						'description' => 'Success',
						'disableCode' => $dis_code
					);
					echo json_encode($return);
					die();
				}
				else{
					returnError("WRONG_TOTP");
				}
			}
			else{
				returnError("TOTP_WAS_ENABLED_BEFORE");
			}
		}
		if ($method == "disable") {
			if ($uinfo['2fa_active'] == 1) {
				if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 10, 60)) {
					returnError("RATE_LIMIT_EXCEEDED");
				}
				require_once 'libs' . DIRECTORY_SEPARATOR . "2fa_utils.php";

				$otp = $_REQUEST['otp'];
				$totp_instance = TOTPInstance();
				$base32 = Base32Instance();

				$secret = $uinfo['2fa_secret'];
				$secret = $base32->decode($secret);

				$key = $totp_instance->GenerateToken($secret);

				if ($key == $otp) {
					$login_db->setTOTPState($user_id, 0);

					$return = array(
						'result' => "OK",
						'description' => 'Success'
					);
					echo json_encode($return);
					die();
				}
				else{
					returnError("WRONG_TOTP");
				}
			}
			else{
				returnError("TOTP_WAS_DISABLED_BEFORE");
			}
		}
	}



	if ($section == "integration" && $token_scopes['profile_management']) {
		if ($method == "getUserProjects") {
			$projects = $login_db->getUserProjects($user_id);

			$return = array(
				'result' => "OK",
				'projects' => $projects
			);
			echo json_encode($return);
			die();
		}
		if ($method == "createProject") {
			if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 5, 60)) {
				returnError("RATE_LIMIT_EXCEEDED");
			}
			if (!$enable_creation && $uinfo['verified'] != 1 && !$allowed_admins[$user_id]) {
				returnError("PROJECT_CREATION_WAS_DISABLED");
			}
			if ($login_db->countUserProjects($user_id) >= $integrations_limit && $uinfo['verified'] != 1 && !$allowed_admins[$user_id]) {
				returnError("REACHED_LIMIT_OF_PROJECTS");
			}
			if (strlen($_REQUEST['name']) < 3 or strlen($_REQUEST['name']) > 32) {
				returnError("TOO_LONG_OR_TOO_SHORT");
			}

			$login_db->createProject($user_id, htmlentities($_REQUEST['name']));

			$return = array(
				'result' => "OK",
				'description' => 'Success'
			);
			echo json_encode($return);
			die();
		}
		if ($method == "getProjectInfo") {
			$project = $login_db->getProjectInfo($_REQUEST['project']);
			if ($project['owner_id'] != $user_id) {
				returnError("UNAUTHORIZED");
			}
			$return = array(
				'result' => "OK",
				'project_id' => $project['project_id'],
				'project_name' => $project['project_name'],
				'redirect_uri' => $project['redirect_uri'],
				'secret_key' => $project['secret_key'],
				'public_key' => $project['public_key'],
				'verified' => $project['verified']
			);
			echo json_encode($return);
			die();
		}

		if ($method == "issueNewPublic") {
			$project = $login_db->getProjectInfo($_REQUEST['project']);
			if ($project['owner_id'] != $user_id) {
				returnError("UNAUTHORIZED");
			}
			$login_db->regenerateProjectPublic($project['project_id'], $project['owner_id'], $project['project_name']);
			$return = array(
				'result' => "OK",
				'description' => "Success"
			);
			echo json_encode($return);
			die();
		}

		if ($method == "issueNewSecret") {
			$project = $login_db->getProjectInfo($_REQUEST['project']);
			if ($project['owner_id'] != $user_id) {
				returnError("UNAUTHORIZED");
			}
			$login_db->regenerateProjectSecret($project['project_id'], $project['owner_id'], $project['project_name']);
			$return = array(
				'result' => "OK",
				'description' => "Success"
			);
			echo json_encode($return);
			die();
		}

		if ($method == "changeRedirect") {
			$project = $login_db->getProjectInfo($_REQUEST['project']);
			if ($project['owner_id'] != $user_id) {
				returnError("UNAUTHORIZED");
			}
			$login_db->changeRedirectURL($project['project_id'], $_REQUEST['redirect_url']);
			$return = array(
				'result' => "OK",
				'description' => "Success"
			);
			echo json_encode($return);
			die();
		}

		if ($method == "changeName") {
			$project = $login_db->getProjectInfo($_REQUEST['project']);
			if ($project['owner_id'] != $user_id) {
				returnError("UNAUTHORIZED");
			}
			if (strlen($_REQUEST['name']) < 3 or strlen($_REQUEST['name']) > 32) {
				returnError("TOO_LONG_OR_TOO_SHORT");
			}

			$login_db->changeProjectName($project['project_id'], htmlentities($_REQUEST['name']));

			$return = array(
				'result' => "OK",
				'description' => "Success"
			);
			echo json_encode($return);
			die();
		}
		if ($method == "delete") {
			if (isRateExceeded($section . '-' . $method, $_SERVER['REMOTE_ADDR'], 5, 60)) {
				returnError("RATE_LIMIT_EXCEEDED");
			}
			$project = $login_db->getProjectInfo($_REQUEST['project']);
			if ($project['owner_id'] != $user_id) {
				returnError("UNAUTHORIZED");
			}
			$login_db->deleteProject($project['project_id']);
			$return = array(
				'result' => "OK",
				'description' => "Success"
			);
			echo json_encode($return);
			die();
		}
	}

	if ($section == "register" && $token_scopes['profile_management']) {
		if ($method == "saveInfo") {
			$user_nick = $_REQUEST['user_nick'];
			$user_name = $_REQUEST['user_name'];
			$user_surname = $_REQUEST['user_surname'];
			$birthday = $_REQUEST['birthday'];

			if ((preg_match("/[^a-zA-Z0-9\-_]+/", $user_nick) || mb_strlen($user_nick) > 16 || mb_strlen($user_nick) < 3 || $login_db->isNickUsed($user_nick)) && $user_nick != $uinfo['user_nick']) {
				returnError("MALFORMED_NICK");
			}

			if (!preg_match("/^[a-zA-Zа-яёА-ЯЁ]+$/u", $user_name) || mb_strlen($user_name) < 2 || mb_strlen($user_name) > 32) {
				returnError("MALFORMED_NAME");
			}

			if (!preg_match("/^[a-zA-Zа-яёА-ЯЁ]+$/u", $user_surname) || mb_strlen($user_surname) < 2 || mb_strlen($user_surname) > 32) {
				returnError("MALFORMED_SURNAME");
			}

			if (0 >= intval($birthday)) {
				returnError("MALFORMED_BIRTHDAY");
			}

			$login_db->saveUserInfo($user_id, $user_nick, $user_name, $user_surname, $birthday);
			$return = array(
				'result' => "OK",
				'description' => 'Success'
			);
			echo json_encode($return);
			die();
		}
	}

	if ($section == "admin" && $token_scopes['admin'] && $allowed_admins[$user_id]) {
		if ($method == "getStats") {
			$request_st = $login_db->getRequestStats();
			$user_st = $login_db->getUserStats();
			$project_st = $login_db->getProjectStats();
			$return = array(
				'result' => "OK",
				'requests' => $request_st,
				'users' => $user_st,
				'projects' => $project_st
			);
			echo json_encode($return);
			die();
		}

		if ($method == "purgeRequests") {
			$login_db->cleanupRequests();
			$return = array(
				'result' => "OK",
				'description' => 'Success'
			);
			echo json_encode($return);
			die();
		}

		if ($method == "getProjectInfo") {
			$project = $login_db->getAdminProjectInfo($_REQUEST['project_id']);
			if (!$project["exists"]) {
				returnError("UNKNOWN_PROJECT");
			}
			$return = array(
				'result' => "OK",
				'project_id' => $project['project_id'],
				'project_name' => $project['project_name'],
				'redirect_uri' => $project['redirect_uri'],
				'verified' => $project['verified'],
				'owner_id' => $project['owner_id'],
				'enabled' => $project['enabled'],
				'banned' => $project['banned']
			);
			echo json_encode($return);
			die();
		}

		if ($method == "deleteProject") {
			$project = $login_db->getAdminProjectInfo($_REQUEST['project_id']);
			if (!$project["exists"]) {
				returnError("UNKNOWN_PROJECT");
			}
			if ($project['enabled'] == 0) {
				$login_db->adminDeleteProject($_REQUEST['project_id']);
				$return = array(
					'result' => "OK",
					'description' => 'Success'
				);
				echo json_encode($return);
				die();
			}
			returnError("PROJECT_CANNOT_BE_DELETED");
		}

		if ($method == "restoreProject") {
			$project = $login_db->getAdminProjectInfo($_REQUEST['project_id']);
			if (!$project["exists"]) {
				returnError("UNKNOWN_PROJECT");
			}
			if ($project['enabled'] == 0) {
				$login_db->adminRestoreProject($_REQUEST['project_id']);
				$return = array(
					'result' => "OK",
					'description' => 'Success'
				);
				echo json_encode($return);
				die();
			}
			returnError("PROJECT_CANNOT_BE_RESTORED");
		}

		if ($method == "toggleProjectVerify") {
			$project = $login_db->getAdminProjectInfo($_REQUEST['project_id']);
			if (!$project["exists"]) {
				returnError("UNKNOWN_PROJECT");
			}
			$login_db->adminVerifyProject($_REQUEST['project_id']);
			$return = array(
				'result' => "OK",
				'description' => 'Success'
			);
			echo json_encode($return);
			die();
		}

		if ($method == "resetProject") {
			$project = $login_db->getAdminProjectInfo($_REQUEST['project_id']);
			if (!$project["exists"]) {
				returnError("UNKNOWN_PROJECT");
			}
			$login_db->changeRedirectURL($project['project_id'], $login_site);
			$return = array(
				'result' => "OK",
				'description' => 'Success'
			);
			echo json_encode($return);
			die();
		}

		if ($method == "getUserInfo") {
			if (is_numeric($_REQUEST['email'])) {
				$test_user_id = $_REQUEST['email'];
			}
			else{
				$test_user_id = $login_db->getUIDByEMail($_REQUEST['email']);
			}
			$user = $login_db->getUserInfo($test_user_id);
			
			if ($user['user_id'] == null) {
				returnError("UNKNOWN_USER");
			}
			
			$is_admin = false;
			if ($allowed_admins[$user['user_id']]) {
				$is_admin = true;
			}
			$return = array(
				'result' => "OK",
				'user_id' => $user['user_id'],
				'user_nick' => $user['user_nick'],
				'user_email' => $user['user_email'],
				'user_name' => $user['user_name'],
				'user_surname' => $user['user_surname'],
				'verified' => $user['verified'],
				'email_check' => $user['email_check'],
				'2fa_active' => $user['2fa_active'],
				'admin' => $is_admin,
				'is_banned' => $user['is_banned'],
				'ban_reason' => $user['ban_reason']
			);
			echo json_encode($return);
			die();
		}

		if ($method == "toggleUserVerify") {
			$user = $login_db->getUserInfo($_GET['user_id']);
			if ($user['user_id'] == "") {
				returnError("UNKNOWN_USER");
			}
			if ($allowed_admins[$user['user_id']]) {
				returnError("UNABLE_TO_TOGGLE_VERIFY");
			}
			$login_db->adminVerifyUser($user['user_id']);
			$return = array(
				'result' => "OK",
				'description' => 'Success'
			);
			echo json_encode($return);
			die();
		}

		if ($method == "resetUserPassword") {
			$user = $login_db->getUserInfo($_GET['user_id']);
			if ($user['user_id'] == "") {
				returnError("UNKNOWN_USER");
			}
			if ($allowed_admins[$user['user_id']]) {
				returnError("UNABLE_TO_MANAGE_USER");
			}
			$login_db->changeUserPassword($user['user_id'], "");
			$return = array(
				'result' => "OK",
				'description' => 'Success'
			);
			echo json_encode($return);
			die();
		}

		if ($method == "resetUserIP") {
			$user = $login_db->getUserInfo($_GET['user_id']);
			if ($user['user_id'] == "") {
				returnError("UNKNOWN_USER");
			}
			if ($allowed_admins[$user['user_id']]) {
				returnError("UNABLE_TO_MANAGE_USER");
			}
			$login_db->setUserIP($user['user_id'], "");
			$return = array(
				'result' => "OK",
				'description' => 'Success'
			);
			echo json_encode($return);
			die();
		}

		if ($method == "resetUserSLID") {
			$user = $login_db->getUserInfo($_GET['user_id']);
			if ($user['user_id'] == "") {
				returnError("UNKNOWN_USER");
			}
			if ($allowed_admins[$user['user_id']]) {
				returnError("UNABLE_TO_MANAGE_USER");
			}
			$login_db->regenerateSLID($user['user_id']);
			$return = array(
				'result' => "OK",
				'description' => 'Success'
			);
			echo json_encode($return);
			die();
		}

		if ($method == "banUser") {
			$user = $login_db->getUserInfo($_GET['user_id']);
			if ($user['user_id'] == "") {
				returnError("UNKNOWN_USER");
			}
			if ($allowed_admins[$user['user_id']]) {
				returnError("UNABLE_TO_MANAGE_USER");
			}
			$login_db->banUser($user['user_id'], $_GET['reason']);
			$return = array(
				'result' => "OK",
				'description' => 'Success'
			);
			echo json_encode($return);
			die();
		}

		if ($method == "unbanUser") {
			$user = $login_db->getUserInfo($_GET['user_id']);
			if ($user['user_id'] == "") {
				returnError("UNKNOWN_USER");
			}
			$login_db->unbanUser($user['user_id']);
			$return = array(
				'result' => "OK",
				'description' => 'Success'
			);
			echo json_encode($return);
			die();
		}
		
		if ($method == "banProject") {
			$project = $login_db->getAdminProjectInfo($_REQUEST['project_id']);
			if (!$project["exists"]) {
				returnError("UNKNOWN_PROJECT");
			}
			$login_db->banProject($project['project_id']);
			$return = array(
				'result' => "OK",
				'description' => 'Success'
			);
			echo json_encode($return);
			die();
		}

		if ($method == "unbanProject") {
			$project = $login_db->getAdminProjectInfo($_REQUEST['project_id']);
			if (!$project["exists"]) {
				returnError("UNKNOWN_PROJECT");
			}
			$login_db->unbanProject($project['project_id']);
			$return = array(
				'result' => "OK",
				'description' => 'Success'
			);
			echo json_encode($return);
			die();
		}
	}

	if ($section == "authentication") {
		if ($method == "getUserInfo") {
			$user_info = array(
				'user_nick' => $uinfo['user_nick'],
				'verified' => $uinfo['verified']
			);

			if ($token_scopes["personal"]) {
				$user_info['user_name'] = $uinfo['user_name'];
				$user_info['user_surname'] = $uinfo['user_surname'];
				$user_info['birthday'] = $uinfo['birthday'];
			}

			if ($token_scopes["email"]) {
				$user_info['user_email'] = $uinfo['user_email'];
			}

			$return = array(
				'result' => "OK",
				'description' => "VALID",
				'user_info' => $user_info
			);
			echo json_encode($return);
			die();
		}
	}

	if ($section == "webauthn") {
		try{
			if ($method === 'getPasskeys') {
				$passkeys_list = $login_db->getPasskeys($uinfo['user_id']);


				$return = array(
					'result' => "OK",
					'keys' => $passkeys_list,
					'attest_format' => $attestation_formats
				);
				echo json_encode($return);
				die();
			}

			if ($method === 'removePasskey') {
				$pkuid = $_GET['PK_UID'];

				$login_db->removePasskey($uinfo['user_id'], $pkuid);

				$return = array(
					'result' => "OK"
				);
				echo json_encode($return);
				die();
			}


			if ($method === 'getNewKeyArgs') {
				$WebAuthn = new lbuchs\WebAuthn\WebAuthn($platform_name, $relying_party_id, null);

				$userId = bin2hex(random_bytes(64));
				$userName = $uinfo['user_email'];
				$userDisplayName = $uinfo['user_nick'];

				$userId = preg_replace('/[^0-9a-f]/i', '', $userId);
				/*$userName = preg_replace('/[^0-9a-z]/i', '_', $userName);
				$userDisplayName = preg_replace('/[^0-9a-z öüäéèàÖÜÄÉÈÀÂÊÎÔÛâêîôû]/i', '_', $userDisplayName);*/

				$createArgs = $WebAuthn->getCreateArgs(hex2bin($userId), $userName, $userDisplayName, 300, true, $user_verification_requirement, null);

				$return = array(
					'result' => "OK",
					'description' => "WAITING_VERIFICATION",
					'args' => $createArgs
				);
				echo json_encode($return);

				$_SESSION['challenge'] = $WebAuthn->getChallenge();
				$_SESSION['pkid'] = $userId;

				die();
			}

			$post = trim(file_get_contents('php://input'));
			if ($post) {
				$post = json_decode($post);
			}

			if ($method === 'createNewKey') {
				$WebAuthn = new lbuchs\WebAuthn\WebAuthn($platform_name, $relying_party_id, null);

				$userName = $uinfo['user_nick'];
				$userDisplayName = $uinfo['user_email'];

				/*$userName = preg_replace('/[^0-9a-z]/i', '_', $userName);
				$userDisplayName = preg_replace('/[^0-9a-z öüäéèàÖÜÄÉÈÀÂÊÎÔÛâêîôû]/i', '_', $userDisplayName);*/

				$clientDataJSON = base64_decode($post->clientDataJSON);
				$attestationObject = base64_decode($post->attestationObject);
				$challenge = $_SESSION['challenge'];

				$data = $WebAuthn->processCreate($clientDataJSON, $attestationObject, $challenge, $user_verification_requirement === "required", true, false);
				$userId = $_SESSION['pkid'];

				$data->userId = $userId;
				$data->userName = $userName;
				$data->userDisplayName = $userDisplayName;

				$credential_id = base64_encode($data->credentialId);

				$passkey_serialized = array(
					"rpId" => $data->rpId,
					"attestationFormat" => $data->attestationFormat,
					"credentialId" => base64_encode($data->credentialId),
					"credentialPublicKey" => $data->credentialPublicKey,
					"certificateChain" => $data->certificateChain,
					"certificate" => $data->certificate,
					"certificateIssuer" => $data->certificateIssuer,
					"certificateSubject" => $data->certificateSubject,
					"signatureCounter" => $data->signatureCounter,
					"AAGUID" => base64_encode($data->AAGUID),
					"rootValid" => $data->rootValid,
					"userPresent" => $data->userPresent,
					"userVerified" => $data->userVerified,
					"userId" => $data->userId,
					"userName" => $data->userName,
					"userDisplayName" => $data->userDisplayName,
				);

				$login_db->savePasskey($uinfo['user_id'], $userId, json_encode($passkey_serialized), $credential_id, $data->attestationFormat);

				$return = array(
					'result' => "OK",
					'description' => "SUCCESS"
				);
				echo json_encode($return);
				die();
			}
		}
		catch(Exception $e){
			echo($e);
			returnError("FAILED_TO_AUTHENTICATE");
		}
	}
}

returnError("UNKNOWN_METHOD_OR_SECTION");

?>