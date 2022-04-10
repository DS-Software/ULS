<?php
require_once 'config.php';
require_once 'database.php';
require_once 'email_templates.php';
require_once 'email_handler.php';
require_once 'encryption.php';
require_once "libs/Base32.php";
require_once "libs/Hotp.php";
require_once "libs/Totp.php";
require_once "libs/browser_libs.php";
require_once "apps/integration_config.php";

use lfkeitel\phptotp\{Base32, Totp};

function returnError($message){
	$error = array(
		'result' => 'FAULT',
		'reason' => $message
	);

	echo(json_encode($error, 1));
	die();
}

function hasFinishedRegister($user_info){
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

function checkLoggedIn($user_id, $SLID, $email, $session, $user_ip, $user_key, $user_info){
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

function checkDisposableEmail($email){
	global $spam_provider;

	$link = $spam_provider . urlencode($email);
	$curl = curl_init($link);
	curl_setopt($curl, CURLOPT_URL, $link);
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

	$resp = curl_exec($curl);
	curl_close($curl);

	$response = json_decode($resp, true);

	if ($response['disposable']) {
		return true;
	}
	return false;
}

function getAPIToken(){
	$headers = "";
	if (isset($_SERVER['Authorization'])) {
		$headers = trim($_SERVER["Authorization"]);
	} else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
		$headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
	} elseif (function_exists('apache_request_headers')) {
		$requestHeaders = apache_request_headers();
		$requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
		if (isset($requestHeaders['Authorization'])) {
			$headers = trim($requestHeaders['Authorization']);
		}
	}

	$token_raw = explode(" ", $headers);
	if ($token_raw[0] == "Bearer") {
		$token = $token_raw[1];
	} else {
		$token = null;
	}

	return $token;
}

function convBase($num, $base_a, $base_b){
	return gmp_strval(gmp_init($num, $base_a), $base_b);
}

function uniqidReal($length = 16){
	$bytes = random_bytes(ceil((($length + 1) / 2)));
	return substr(bin2hex($bytes), 0, $length);
}

if ($maintenance_mode) {
	returnError("MAINTENANCE_MODE");
}

$login_db = new database($database);

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

		$ver_user_info = $login_db->getUserInfo($user_id);

		$verified = checkLoggedIn($user_id, $SLID, $email, $session, $user_ip, $user_key, $ver_user_info);

		if ($ip_verify != hash('sha256', "{$session}_{$ver_user_info['user_id']}_{$_SERVER['REMOTE_ADDR']}_$service_key") && $verified) {
			$return = array(
				'result' => 'OK',
				'description' => 'IPVerificationNeeded',
				'token' => null
			);

			echo(json_encode($return, 1));
			die();
		}

		if ($ver_user_info['2fa_active'] == 1 && $verified) {
			if ($totp_timestamp + 2678400 < time()) {
				setcookie('totp_timestamp', '', 0, $domain_name);
				setcookie('totp_verification', '', 0, $domain_name);
				$totp_timestamp = null;
				$totp_verification = null;
			}

			$true_totp_ver = hash("sha512", "{$SLID}_{$ver_user_info['2fa_secret']}_{$ver_user_info['user_id']}_$totp_timestamp");

			if ($true_totp_ver != $totp_verification && $verified) {
				$verified = false;
				$return = array(
					'result' => 'OK',
					'description' => '2faVerificationRequired',
					'token' => null
				);

				echo(json_encode($return, 1));
				die();
			}
		}

		if ($verified) {
			$scopes = getScopes('all', 1);
			$at_seed = bin2hex(random_bytes(32));

			$access_token = array(
				'uls_id' => $ver_user_info['user_id'],
				'seed' => $at_seed,
				'scopes' => $scopes,
				'sign' => hash('sha512', $ver_user_info['user_id'] . "_" . $at_seed . "_" . json_encode($scopes) . "_" . $ver_user_info['api_key_seed'] . "_" . $service_key)
			);

			$access_token = base64_encode(json_encode($access_token));

			if (!hasFinishedRegister($ver_user_info)) {
				$return = array(
					'result' => 'OK',
					'description' => 'unfinishedReg',
					'token' => $access_token
				);

				echo(json_encode($return, 1));
				die();
			}

			$return = array(
				'result' => 'OK',
				'token' => $access_token
			);

			echo(json_encode($return, 1));
		} else {
			setcookie('user_verkey', '', 0, $domain_name);
			setcookie('user_ip', '', 0, $domain_name);
			setcookie('session', '', 0, $domain_name);
			setcookie('email', '', 0, $domain_name);
			setcookie('SLID', '', 0, $domain_name);
			setcookie('user_id', '', 0, $domain_name);
			setcookie('ip_verify', '', 0, $domain_name);
			returnError("WRONG_LOGIN_INFO");
		}
		die();
	}

	if ($method == "authorize") {
		$login = $_REQUEST['login'];
		$password = $_REQUEST['password'];
		if (checkDisposableEmail($login)) {
			returnError("DISPOSABLE_EMAIL");
		}

		usleep(random_int(0, 999999));

		$log_user_id = $login_db->getUIDByEMail($login);
		if (is_int($log_user_id)) {
			$user_info = $login_db->getUserInfo($log_user_id);
			$true_password_hash = $user_info['password_hash'];
			$password_hash = hash("sha512", $password . "_" . $user_info['salt']);
			if ($password_hash != $true_password_hash) {
				returnError('WRONG_CREDENTIALS');
			}
		} else {
			returnError('WRONG_CREDENTIALS');
		}

		if ($_SERVER['REMOTE_ADDR'] == $user_info['user_ip']) {
			$rsid = bin2hex(random_bytes($session_length / 2));
			$timestamp = time();
			$session_id = hash('sha256', $rsid . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);

			$ip_verify = hash('sha256', "{$session_id}_{$log_user_id}_{$_SERVER['REMOTE_ADDR']}_$service_key");

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

		} else {
			$ip_ver_code = strtoupper(uniqidReal(8));
			$login_db->setIPCode($log_user_id, $ip_ver_code);

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
				'description' => 'emailVerificationNeeded'
			);
		}
		echo(json_encode($return));
		die();
	}

	if ($method == 'verifyIP') {
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
				$true_code = $login_db->getIPCode($user_id);

				if ($code == $true_code) {
					$ip_verify = hash('sha256', "{$session}_{$user_id}_{$_SERVER['REMOTE_ADDR']}_$service_key");

					setcookie("ip_verify", $ip_verify, time() + 2678400, $domain_name);
					$login_db->setUserIP($user_id, $_SERVER['REMOTE_ADDR']);
					$login_db->clearIPCode($user_id);

					$return = array(
						'result' => 'OK',
						'description' => 'Success'
					);

					echo(json_encode($return));
					die();
				} else {
					returnError("WRONG_VER_CODE");
				}
			}
		}
		returnError("WRONG_CREDENTIALS");
	}

	if ($method == 'sendRegisterMessage') {
		$login = $_REQUEST['login'];

		if (checkDisposableEmail($login)) {
			returnError("DISPOSABLE_EMAIL");
		}

		if (!filter_var($login, FILTER_VALIDATE_EMAIL)) {
			returnError("INVALID_EMAIL");
		}
		$password = $_REQUEST['password'];

		if (!$login_db->wasEmailRegistered($login)) {
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
			'description' => 'emailVerificationNeeded'
		);
		echo(json_encode($return));
		die();
	}

	if ($method == "registerNewUser") {
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

		if ($timestamp + 900 >= time()) {
			if (!$login_db->wasEmailRegistered($login)) {
				$true_session_id = hash('sha256', $rand_session_id . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);
				if ($true_session_id == $session_id) {
					$true_register_verify = hash("sha256", $password_hash . "_" . $service_key . "_" . $session_id);
					if ($true_register_verify == $register_verify) {
						$real_password = safe_decrypt($password_hash, $encryption_key);
						if ($real_password !== False) {
							$true_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $real_password . '_' . $timestamp . "_" . $session_id);
							if ($true_ver_id == $email_ver_id) {

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

								$ip_verify = hash('sha256', "{$session_id}_{$user_id}_{$_SERVER['REMOTE_ADDR']}_$service_key");
								setcookie("ip_verify", $ip_verify, time() + 2678400, $domain_name);

								$login_db->setUserIP($user_id, $_SERVER['REMOTE_ADDR']);

								$return = array(
									'result' => 'OK',
									'description' => 'Success'
								);
								echo(json_encode($return));
							} else {
								returnError("UNABLE_TO_CREATE_ACCOUNT");
							}
						} else {
							returnError("UNABLE_TO_CREATE_ACCOUNT");
						}
					} else {
						returnError("UNABLE_TO_CREATE_ACCOUNT");
					}
				} else {
					returnError("UNABLE_TO_CREATE_ACCOUNT");
				}
			} else {
				returnError("UNABLE_TO_CREATE_ACCOUNT");
			}
		} else {
			returnError("UNABLE_TO_CREATE_ACCOUNT");
		}
		die();
	}

	if ($method == 'sendRestoreEmail') {
		$login = $_REQUEST['login'];
		if (!filter_var($login, FILTER_VALIDATE_EMAIL)) {
			returnError("INVALID_EMAIL");
		}
		if (checkDisposableEmail($login)) {
			returnError("DISPOSABLE_EMAIL");
		}

		if ($login_db->wasEmailRegistered($login)) {
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
			'description' => 'emailVerificationNeeded'
		);
		echo(json_encode($return));
		die();
	}
	if ($method == "restorePassword") {
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
		} else {
			$log_user_id = $login_db->getUIDByEMail($login);
			$user_info = $login_db->getUserInfo($log_user_id);

			$true_session_id = hash('sha256', $rand_session_id . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);
			$true_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $timestamp . "_" . $user_info['SLID'] . "_" . $session_id);
			$last_sid = $login_db->getLastSID($log_user_id);

			if ($true_ver_id == $email_ver_id && $timestamp + 900 > time()) {
				if ($session_id == $true_session_id) {
					if ($last_sid == $session_id) {
						if ($login_db->wasEmailRegistered($login)) {
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

							$ip_verify = hash('sha256', "{$session_id}_{$log_user_id}_{$_SERVER['REMOTE_ADDR']}_$service_key");
							setcookie("ip_verify", $ip_verify, time() + 2678400, $domain_name);

							$return = array(
								'result' => 'OK',
								'description' => 'Success'
							);

							echo(json_encode($return));
						} else {
							returnError("UNABLE_TO_CHANGE_PASSWORD");
						}
					} else {
						returnError("UNABLE_TO_CHANGE_PASSWORD");
					}
				} else {
					returnError("UNABLE_TO_CHANGE_PASSWORD");
				}
			} else {
				returnError("UNABLE_TO_CHANGE_PASSWORD");
			}
		}
		die();
	}

	if ($method == "changeUserEMail") {
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
		$last_sid = $login_db->getLastSID($user_id);

		if ($true_ver_id == $email_ver_id && $timestamp + 900 > time()) {
			if ($session_id == $true_session_id) {
				if ($last_sid == $session_id) {
					if (!$login_db->wasEmailRegistered($new_mail)) {
						$login_db->changeUserEmail($user_id, $new_mail);

						$login_db->clearLastSID($user_id);

						$return = array(
							'result' => 'OK',
							'description' => 'Success'
						);

						echo(json_encode($return));
					} else {
						returnError("UNABLE_TO_CHANGE_EMAIL");
					}
				} else {
					returnError("UNABLE_TO_CHANGE_EMAIL");
				}
			} else {
				returnError("UNABLE_TO_CHANGE_EMAIL");
			}
		} else {
			returnError("UNABLE_TO_CHANGE_EMAIL");
		}
		die();
	}

	if ($method == "checkTOTP") {
		$user_id = $_COOKIE['user_id'];
		$SLID = $_COOKIE['SLID'];
		$email = $_COOKIE['email'];
		$session = $_COOKIE['session'];
		$user_ip = $_COOKIE['user_ip'];
		$user_key = $_COOKIE['user_verkey'];
		$otp = $_REQUEST['otp'];

		$ver_user_info = $login_db->getUserInfo($user_id);

		$verified = checkLoggedIn($user_id, $SLID, $email, $session, $user_ip, $user_key, $ver_user_info);

		if ($ver_user_info['2fa_active'] != 1) {
			returnError("2FA_IS_NOT_ENABLED");
		}

		if ($verified) {
			$user_info = $login_db->getUserInfo($user_id);
			if ($user_info['user_id'] == $user_id && $user_id != "") {
				$totp_instance = new Totp();
				$base32 = new Base32();

				$secret = $user_info['2fa_secret'];
				$secret = $base32->decode($secret);

				$key = $totp_instance->GenerateToken($secret);

				if ($otp == $key) {
					$totp_timestamp = time();
					$true_totp_ver = hash("sha512", "{$SLID}_{$ver_user_info['2fa_secret']}_{$ver_user_info['user_id']}_$totp_timestamp");

					setcookie("totp_timestamp", $totp_timestamp, time() + 2678400, $domain_name);
					setcookie("totp_verification", $true_totp_ver, time() + 2678400, $domain_name);

					$return = array(
						'result' => 'OK',
						'description' => 'Success'
					);

					echo(json_encode($return));
					die();
				} else {
					returnError("WRONG_2FA_CODE");
				}
			}
		}
		returnError("WRONG_CREDENTIALS");
	}

	if ($method == "disableTOTP") {
		$user_id = $_COOKIE['user_id'];
		$SLID = $_COOKIE['SLID'];
		$email = $_COOKIE['email'];
		$session = $_COOKIE['session'];
		$user_ip = $_COOKIE['user_ip'];
		$user_key = $_COOKIE['user_verkey'];
		$key = $_REQUEST['key'];

		$ver_user_info = $login_db->getUserInfo($user_id);

		$verified = checkLoggedIn($user_id, $SLID, $email, $session, $user_ip, $user_key, $ver_user_info);

		if ($ver_user_info['2fa_active'] != 1) {
			returnError("2FA_IS_NOT_ENABLED");
		}

		if ($verified) {
			$user_info = $login_db->getUserInfo($user_id);
			if ($user_info['user_id'] == $user_id && $user_id != "") {
				$hash_code = hash('sha256', $key . "_" . $user_id);
				if ($hash_code == $user_info['2fa_disable_code']) {
					$login_db->disableTOTP($user_id);
					$return = array(
						'result' => "OK",
						'description' => "Success"
					);

					echo(json_encode($return));
					die();
				} else {
					returnError("WRONG_DISABLE_KEY");
				}
			}
		}

		returnError("WRONG_CREDENTIALS");
	}

	if ($method == "getELSession") {
		$login_db->cleanUpSessions();

		if ($login_db->countSessionsByIP($_SERVER['REMOTE_ADDR']) >= 10) {
			$login_db->deleteSessionsByIP($_SERVER['REMOTE_ADDR']);
			returnError("RATE_LIMIT_FOR_THIS_IP");
		}

		$session = "session_" . convBase(uniqidReal(256), 16, 36);
		$sess_salt = convBase(uniqidReal(32), 16, 36);
		$login_db->createELSession($session, $sess_salt, $_SERVER['REMOTE_ADDR']);

		$session_ver = hash("sha256", $session . "_" . $service_key . "_" . $sess_salt . "_" . $_SERVER['REMOTE_ADDR']);

		$browser = getBrowser();

		$ua = array(
			'browser' => $browser['name'],
			'version' => $browser['version'],
			'platform' => ucfirst($browser['platform']),
			'ip' => $_SERVER['REMOTE_ADDR']
		);

		$ua = json_encode($ua);

		$session_link = base64_encode($login_site . "/easylogin_accept.php?session_id=" . $session . "&session_ver=" . $session_ver . "&user_agent=" . base64_encode($ua) . "&user_agent_ver=" . hash("sha256", $ua . "_" . $service_key));

		$session_qr = "/gen_2fa_qr.php?method=EasyLoginSession&session=" . $session_link;

		$return = array(
			'result' => "OK",
			'session' => $session,
			'session_qr' => $session_qr,
			'session_verifier' => $session_ver
		);

		echo(json_encode($return));
		die();
	}

	if ($method == "removeELSession") {
		$login_db->cleanUpSessions();
		$session = $login_db->getELSession($_REQUEST['session_id']);

		if ($session['session'] != '') {
			$true_sess_ver = hash("sha256", $session['session'] . "_" . $service_key . "_" . $session['session_seed'] . "_" . $_SERVER['REMOTE_ADDR']);

			if ($true_sess_ver == $_REQUEST['session_ver']) {
				$login_db->deleteELSession($session['session']);
				$return = array(
					'result' => "OK",
					'description' => "Success"
				);

				echo(json_encode($return));
			} else {
				returnError("UNAUTHORIZED");
			}
		} else {
			returnError("WRONG_SESSION");
		}
		die();
	}

	if ($method == "checkELSession") {
		$login_db->cleanUpSessions();
		$session = $login_db->getELSession($_REQUEST['session_id']);

		if ($session['session'] == '') {
			returnError("WRONG_SESSION");
		}

		$true_sess_ver = hash("sha256", $session['session'] . "_" . $service_key . "_" . $session['session_seed'] . "_" . $_SERVER['REMOTE_ADDR']);

		if ($true_sess_ver != $_REQUEST['session_ver']) {
			returnError("UNAUTHORIZED");
		}

		if ($session['claimed'] != 1) {
			returnError("UNCLAIMED");
		}

		$user_info = $login_db->getUserInfo($session['user_id']);

		if ($user_info['easylogin'] != 1) {
			returnError("THIS_FEATURE_WAS_DISABLED_BY_OWNER");
		}

		if ($_SERVER['REMOTE_ADDR'] != $session['ip']) {
			returnError("UNKNOWN_IP");
		}

		$rsid = bin2hex(random_bytes($session_length / 2));
		$timestamp = time();

		$login_db->setUserIP($user_info['user_id'], $_SERVER['REMOTE_ADDR']);
		$login_db->deleteELSession($session['session']);

		setcookie("user_id", $user_info['user_id'], time() + 2678400, $domain_name);
		setcookie("email", $user_info['user_email'], time() + 2678400, $domain_name);
		setcookie("user_ip", $_SERVER['REMOTE_ADDR'], time() + 2678400, $domain_name);
		setcookie("user_verkey", hash("sha512", "{$rsid}_{$user_info['user_email']}_{$user_info['user_id']}_{$user_info['SLID']}_{$_SERVER['REMOTE_ADDR']}_$service_key"), time() + 2678400, $domain_name);
		setcookie("session", $rsid, time() + 2678400, $domain_name);
		setcookie("SLID", $user_info['SLID'], time() + 2678400, $domain_name);

		$ip_verify = hash('sha256', "{$rsid}_{$user_info['user_id']}_{$_SERVER['REMOTE_ADDR']}_$service_key");
		setcookie("ip_verify", $ip_verify, time() + 2678400, $domain_name);

		$return = array(
			'result' => 'OK',
			'description' => 'Success'
		);

		echo(json_encode($return));
		die();
	}
} else {
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

	if ($section == "projects" && $token_scopes['profile_management']) {
		if ($method == "login") {
			$project_public = $_REQUEST['public'];
			$project = $login_db->getProjectInfoByPublic($project_public);

			$scopes = getScopes($_REQUEST['scopes']);

			if ($project['project_id'] == "") {
				returnError("UNKNOWN_PROJECT");
			}

			$login_db->updateProjectLastUsed($project['project_id']);

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

			if (strpos($project['redirect_uri'], "?") !== false) {
				$params = "&";
			} else {
				$params = "?";
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
			echo(json_encode($return));
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
				'verified' => $project['infinite'],
				'fault_redirect' => $fault_redirect
			);
			echo(json_encode($return));
			die();
		}
	}
	if ($section == "users" && $token_scopes['profile_management']) {
		if ($method == "getCurrentEmail") {
			$return = array(
				'result' => "OK",
				'email' => $uinfo['user_email'],
				'user_nick' => $uinfo['user_nick'],
				'user_name' => $uinfo['user_name'],
				'user_surname' => $uinfo['user_surname'],
				'user_bday' => $uinfo['birthday'],
				'verified' => $uinfo['verified']
			);

			echo(json_encode($return));
			die();
		}

		if ($method == "regenerateAPIKey") {
			$login_db->regenerateAPIKey($user_id);

			$return = array(
				'result' => "OK",
				'description' => "Success"
			);
			echo(json_encode($return));
			die();
		}

		if ($method == "regenerateSLID") {
			$login_db->regenerateSLID($user_id);

			$return = array(
				'result' => "OK",
				'description' => "Success"
			);
			echo(json_encode($return));
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
				echo(json_encode($return));
				die();
			} else {
				returnError("WRONG_PASSWORD");
			}
		}

		if ($method == "changeUserEmail") {
			$login = $uinfo['user_email'];
			$new_email = $_REQUEST['email'];

			if (checkDisposableEmail($new_email)) {
				returnError("DISPOSABLE_EMAIL");
			}
			if ($new_email != $uinfo['user_email']) {
				if (filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
					if (!$login_db->wasEmailRegistered($new_email)) {
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

						$return = array(
							'result' => 'OK',
							'description' => 'emailVerificationNeeded'
						);

						echo(json_encode($return));
						die();
					}
				} else {
					returnError("INVALID_EMAIL");
				}
			} else {
				returnError("YOU_ARE_CURRENTLY_USING_THIS_EMAIL");
			}
		}
	}

	if ($section == "totp" && $token_scopes['profile_management']) {
		if ($method == "get2FAInfo") {
			$return = array(
				'result' => "OK",
				'totp_active' => $uinfo['2fa_active']
			);
			echo(json_encode($return));
			die();
		}

		if ($method == "prepareEnable") {
			if ($uinfo['2fa_active'] == 0) {
				$first_name = $email_info['$project_name'];
				$email = $uinfo['user_email'];

				$totp_instance = new Totp();
				$base32 = new Base32();

				$secret = $totp_instance->GenerateSecret(16);
				$true_secret = $base32->encode($secret);

				$login_db->setTOTPSecret($user_id, $true_secret);

				$totp_url = "/gen_2fa_qr.php?fn=$first_name&email=$email&secret=$true_secret";

				$return = array(
					'result' => "OK",
					'url' => $totp_url,
					'secret' => $true_secret
				);
				echo(json_encode($return));
				die();
			} else {
				returnError("TOTP_WAS_ENABLED_BEFORE");
			}
		}
		if ($method == "enable") {
			if ($uinfo['2fa_active'] == 0) {
				$otp = $_REQUEST['otp'];
				$totp_instance = new Totp();
				$base32 = new Base32();

				$secret = $uinfo['2fa_secret'];
				$secret = $base32->decode($secret);

				$key = $totp_instance->GenerateToken($secret);

				if ($key == $otp) {
					$dis_code = convBase(uniqidReal(20), 16, 36);

					$login_db->enableTOTP($user_id);
					$login_db->setTOTPDisableCode($user_id, $dis_code);

					$return = array(
						'result' => "OK",
						'description' => 'Success',
						'disableCode' => $dis_code
					);
					echo(json_encode($return));
					die();
				} else {
					returnError("WRONG_TOTP");
				}
			} else {
				returnError("TOTP_WAS_ENABLED_BEFORE");
			}
		}
		if ($method == "disable") {
			if ($uinfo['2fa_active'] == 1) {
				$otp = $_REQUEST['otp'];
				$totp_instance = new Totp();
				$base32 = new Base32();

				$secret = $uinfo['2fa_secret'];
				$secret = $base32->decode($secret);

				$key = $totp_instance->GenerateToken($secret);

				if ($key == $otp) {
					$login_db->disableTOTP($user_id);

					$return = array(
						'result' => "OK",
						'description' => 'Success'
					);
					echo(json_encode($return));
					die();
				} else {
					returnError("WRONG_TOTP");
				}
			} else {
				returnError("TOTP_WAS_DISABLED_BEFORE");
			}
		}
	}

	if ($section == "easylogin" && $token_scopes['profile_management']) {
		if ($method == "getEasyLoginInfo") {
			$return = array(
				'result' => "OK",
				'easylogin_active' => $uinfo['easylogin']
			);
			echo(json_encode($return));
			die();
		}

		if ($method == "enable") {
			if ($uinfo['easylogin'] == 0) {
				$login_db->enableEasyLogin($user_id);

				$return = array(
					'result' => "OK",
					'desc' => 'Success'
				);
				echo(json_encode($return));
				die();
			} else {
				returnError("EASYLOGIN_WAS_ENABLED_BEFORE");
			}
		}

		if ($method == "disable") {
			if ($uinfo['easylogin'] == 1) {
				$login_db->disableEasyLogin($user_id);

				$return = array(
					'result' => "OK",
					'desc' => 'Success'
				);
				echo(json_encode($return));
				die();
			} else {
				returnError("EASYLOGIN_WAS_DISABLED_BEFORE");
			}
		}

		if ($method == "claim") {
			$login_db->cleanUpSessions();
			$session = $login_db->getELSession($_REQUEST['session_id']);

			if ($session['session'] != '') {
				$true_sess_ver = hash("sha256", $session['session'] . "_" . $service_key . "_" . $session['session_seed'] . "_" . $session['ip']);

				if ($true_sess_ver == $_REQUEST['session_ver']) {
					if ($session['created'] + 300 >= time()) {
						$user_info = $login_db->getUserInfo($user_id);
						if ($user_info['easylogin'] == 1) {
							if ($user_info['2fa_active'] == 1) {
								$login_db->claimELSession($user_id, $session['session']);

								$return = array(
									'result' => "OK",
									'desc' => 'Success'
								);
								echo(json_encode($return));
								die();
							} else {
								returnError("2FA_DISABLED");
							}
						} else {
							returnError("THIS_FEATURE_WAS_DISABLED_BY_OWNER");
						}
					} else {
						$login_db->deleteELSession($session['session']);
						returnError("TIMEOUT");
					}
				} else {
					returnError("UNAUTHORIZED");
				}
			} else {
				returnError("WRONG_SESSION");
			}
		}
	}

	if ($section == "integration" && $token_scopes['profile_management']) {
		if ($method == "getUserProjects") {
			$projects = $login_db->getUserProjects($user_id);
			$login_db->cleanUpProjects($delete_projects_on_inactivity, $deletion_timeout);

			$return = array(
				'result' => "OK",
				'projects' => $projects
			);
			echo(json_encode($return));
			die();
		}
		if ($method == "createProject") {
			if ($login_db->countUserProjects($user_id) >= 15 && $uinfo['verified'] != 1) {
				returnError("REACHED_LIMIT_OF_PROJECTS");
			}
			if (strlen($_REQUEST['name']) < 3 or strlen($_REQUEST['name']) > 32) {
				returnError("TOO_LONG_OR_TOO_SHORT");
			}

			$login_db->createProject($user_id, htmlentities($_REQUEST['name']));

			$return = array(
				'result' => "OK"
			);
			echo(json_encode($return));
			die();
		}
		if ($method == "getProjectInfo") {
			$project = $login_db->getProjectInfo($_REQUEST['project']);
			$login_db->cleanUpProjects($delete_projects_on_inactivity, $deletion_timeout);
			if ($project['owner_id'] != $user_id) {
				returnError("UNAUTHORIZED");
			}
			$return = array(
				'result' => "OK",
				'project_id' => $project['project_id'],
				'project_name' => $project['project_name'],
				'redirect_uri' => $project['redirect_uri'],
				'secret_key' => $project['secret_key'],
				'public_key' => $project['public_key']
			);
			echo(json_encode($return));
			die();
		}

		if ($method == "issueNewPublic") {
			$project = $login_db->getProjectInfo($_REQUEST['project']);
			$login_db->cleanUpProjects($delete_projects_on_inactivity, $deletion_timeout);
			if ($project['owner_id'] != $user_id) {
				returnError("UNAUTHORIZED");
			}
			$login_db->regenerateProjectPublic($project['project_id'], $project['owner_id'], $project['project_name']);
			$return = array(
				'result' => "OK"
			);
			echo(json_encode($return));
			die();
		}

		if ($method == "issueNewSecret") {
			$project = $login_db->getProjectInfo($_REQUEST['project']);
			$login_db->cleanUpProjects($delete_projects_on_inactivity, $deletion_timeout);
			if ($project['owner_id'] != $user_id) {
				returnError("UNAUTHORIZED");
			}
			$login_db->regenerateProjectSecret($project['project_id'], $project['owner_id'], $project['project_name']);
			$return = array(
				'result' => "OK"
			);
			echo(json_encode($return));
			die();
		}

		if ($method == "changeRedirect") {
			$project = $login_db->getProjectInfo($_REQUEST['project']);
			$login_db->cleanUpProjects($delete_projects_on_inactivity, $deletion_timeout);
			if ($project['owner_id'] != $user_id) {
				returnError("UNAUTHORIZED");
			}
			$login_db->changeRedirectURL($project['project_id'], $_REQUEST['redirect_url']);
			$return = array(
				'result' => "OK"
			);
			echo(json_encode($return));
			die();
		}

		if ($method == "changeName") {
			$project = $login_db->getProjectInfo($_REQUEST['project']);
			$login_db->cleanUpProjects($delete_projects_on_inactivity, $deletion_timeout);
			if ($project['owner_id'] != $user_id) {
				returnError("UNAUTHORIZED");
			}
			if (strlen($_REQUEST['name']) < 3 or strlen($_REQUEST['name']) > 32) {
				returnError("TOO_LONG_OR_TOO_SHORT");
			} else {
				$login_db->changeProjectName($project['project_id'], htmlentities($_REQUEST['name']));

				$return = array(
					'result' => "OK"
				);
				echo(json_encode($return));
				die();
			}
		}
		if ($method == "delete") {
			$project = $login_db->getProjectInfo($_REQUEST['project']);
			$login_db->cleanUpProjects($delete_projects_on_inactivity, $deletion_timeout);
			if ($project['owner_id'] != $user_id) {
				returnError("UNAUTHORIZED");
			}
			$login_db->deleteProject($project['project_id']);
			$return = array(
				'result' => "OK"
			);
			echo(json_encode($return));
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

			if ($birthday == 0) {
				returnError("MALFORMED_BIRTHDAY");
			}

			$login_db->saveUserInfo($user_id, $user_nick, $user_name, $user_surname, $birthday);
			$return = array(
				'result' => "OK"
			);
			echo(json_encode($return));
			die();
		}
	}

	if ($section == "authentication") {
		if ($method == "getUserInfo") {
			$user_info = array(
				'user_nick' => $uinfo['user_nick'],
				'verified' => $uinfo['verified'],
				'user_ip' => $_SERVER['REMOTE_ADDR']
			);

			if ($token_scopes["personal"]) {
				$user_info['user_name'] = $uinfo['user_name'];
				$user_info['user_surname'] = $uinfo['user_surname'];
				$user_info['birthday'] = $uinfo['birthday'];
			}

			if ($token_scopes["email"]) {
				$user_info['user_email'] = $uinfo['user_email'];
			}

			$user_info = base64_encode(json_encode($user_info));
			$return = array(
				'result' => "OK",
				'description' => "VALID",
				'user_info' => $user_info
			);
			echo(json_encode($return));
			die();
		}
	}
}

returnError("UNKNOWN_METHOD_OR_SECTION");

?>