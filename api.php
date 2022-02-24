<?php
require_once 'config.php';
require_once 'database.php';
require_once 'email_templates.php';
require_once 'encryption.php';
require_once "libs/Base32.php";
require_once "libs/Hotp.php";
require_once "libs/Totp.php";
require_once "libs/browser_libs.php";
require_once "apps/integration_config.php";

use lfkeitel\phptotp\{Base32,Totp};

function returnError($message){
	$error = array(
		'result' => 'FAULT',
		'reason' => $message
	);

	echo(json_encode($error, 1));
	die();
}

function convBase($num, $base_a, $base_b)
{
    return gmp_strval (gmp_init($num, $base_a), $base_b );
}

function uniqidReal($length = 16) {
    $bytes = random_bytes(ceil((($length+1) / 2)));
	return substr(bin2hex($bytes), 0, $length);
}

if($maintenance_mode){
	returnError("MAINTENANCE_MODE");
}

$login_db = new database($database);

$method = $_REQUEST['method'];
$section = $_REQUEST['section'];

if($method == '' OR $section == ''){
	returnError('NO_SECTION_OR_METHOD_SPECIFIED');
}

if($section == "UNAUTH"){
	if($method == "getAccessToken"){
		$user_id = $_COOKIE['user_id'];
		$SLID = $_COOKIE['SLID'];
		$email = $_COOKIE['email'];
		$session = $_COOKIE['session'];
		$user_ip = $_COOKIE['user_ip'];
		$user_key = $_COOKIE['user_verkey'];
		$totp_timestamp = $_COOKIE['totp_timestamp'];
		$totp_verification = $_COOKIE['totp_verification'];
		
		$verified = false;
		
		$ver_user_info = $login_db->get_user_info($user_id);
		if($ver_user_info['user_id'] == $user_id && $ver_user_info['user_id'] != null){
			if($ver_user_info['SLID'] == $SLID){
				if($user_ip == $_SERVER['REMOTE_ADDR']){
					$true_hash = hash("sha512", "{$session}_{$email}_{$user_id}_{$SLID}_{$_SERVER['REMOTE_ADDR']}_{$service_key}");
					
					if($true_hash == $user_key){
						$verified = true;
					}
				}
			}
		}
		
		if($ver_user_info['2fa_active'] == 1){
			
			if($totp_timestamp + 2678400 < time()){
				setcookie('totp_timestamp', '', 0, $domain_name);
				setcookie('totp_verification', '', 0, $domain_name);
				$totp_timestamp = null;
				$totp_verification = null;
			}
			
			$true_totp_ver = hash("sha512", "{$SLID}_{$ver_user_info['2fa_secret']}_{$ver_user_info['user_id']}_{$totp_timestamp}");
			
			if($_REQUEST['totp_logout'] == "true"){
				setcookie('user_verkey', '', 0, $domain_name);
				setcookie('user_ip', '', 0, $domain_name);
				setcookie('session', '', 0, $domain_name);
				setcookie('email', '', 0, $domain_name);
				setcookie('SLID', '', 0, $domain_name);
				setcookie('user_id', '', 0, $domain_name);
				
				die();
			}
			
			if($true_totp_ver != $totp_verification && $verified){
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
		
		if($verified){
			$token_main_part = hash('sha512', $service_key . $user_id . $ver_user_info['api_key_seed']);
			$token = $user_id . ":" . $token_main_part;
			$return = array(
				'result' => 'OK',
				'token' => $token
			);
			
			echo(json_encode($return, 1));
		}
		else{
			setcookie('user_verkey', '', 0, $domain_name);
			setcookie('user_ip', '', 0, $domain_name);
			setcookie('session', '', 0, $domain_name);
			setcookie('email', '', 0, $domain_name);
			setcookie('SLID', '', 0, $domain_name);
			setcookie('user_id', '', 0, $domain_name);
			returnError("WRONG_LOGIN_INFO");
		}
	}
	
	if($method == "getAuthChallenge"){
		$rsid = bin2hex(random_bytes($session_length / 2));
		$timestamp = time();
		$session_id = hash('sha256', $rsid . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);
		$session = array(
			'session_id' => $session_id,
			'timestamp' => $timestamp,
			'rand_session_id' => $rsid,
			'user_ip' => $_SERVER['REMOTE_ADDR']
		);
		echo(json_encode($session));
	}
	
	if($method == 'verifyAuthChallenge'){
		$user_ip = $_SERVER['REMOTE_ADDR'];
		$rand_session_id = $_GET['rand_session_id'];
		$session_id = $_GET['session_id'];
		$timestamp = $_GET['timestamp'];
		$login = $_GET['login'];
		$password_token = $_GET['password_hash'];
		
		$verification = array(
			'session_ver' => false,
			'timestamp' => false,
			'password' => false
			
		);
		
		usleep(random_int(0, 999999));
		
		//session verification
			$true_session_id = hash('sha256', $rand_session_id . "_" . $timestamp . "_" . $user_ip . "_" . $service_key);
			
			if($session_id == $session_id){
				$verification['session_ver'] = true;
			}
			else{
				returnError('WRONG_SESSION');
			}
		// ---
		
		//timestamp verification
			
			if($timestamp + 600 >= time()){
				$verification['timestamp'] = true;
			}
			else{
				returnError('THIS_SESSION_IS_EXPIRED');
			}
		// ---
		
		//password verification
		
			$log_user_id = $login_db->getUIDByEMail($login);
			if(is_int($log_user_id)){
				$user_info = $login_db->get_user_info($log_user_id);
				$true_password_hash = hash('sha256', $user_info['password_hash'] . '_' . $session_id . '_' . $user_ip . '_' . $timestamp . '_' . $rand_session_id . '_' . $login);
				if($true_password_hash == $password_token){
					$verification['password'] = true;
				}
				else{
					returnError('WRONG_CREDENTIALS');
				}
			}
			else{
				returnError('WRONG_CREDENTIALS');
			}
			
		// ---
		
		if($verification['password'] && $verification['timestamp'] && $verification['session_ver']){
			if($user_ip == $user_info['user_ip']){
				//EVERYTHING IS OK

					setcookie("user_id", $log_user_id, time() + 2678400, $domain_name);
					setcookie("email", $login, time() + 2678400, $domain_name);
					setcookie("user_ip", $_SERVER['REMOTE_ADDR'], time() + 2678400, $domain_name);
					setcookie("user_verkey", hash("sha512", "{$session_id}_{$login}_{$log_user_id}_{$user_info['SLID']}_{$_SERVER['REMOTE_ADDR']}_{$service_key}"), time() + 2678400, $domain_name);
					setcookie("session", $session_id, time() + 2678400, $domain_name);
					setcookie("SLID", $user_info['SLID'], time() + 2678400, $domain_name);
					
					$return = array(
						'result' => 'OK',
						'description' => 'Success'
					);
					
					echo(json_encode($return));
				// ---
			}
			else{
				//UNKNOWN IP
					$email_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $session_id . '_' . $user_info['SLID']);
				
					$auth_link = $login_site . "/auth_manager.php?method=emailIPValidation&rand_session_id=$rand_session_id&session_id=$session_id&timestamp=$timestamp&login=$login&password_hash=$password_token&email_ver_id=$email_ver_id";
					
					require_once 'libs/apmailer.php';
		
					class email{
						public function __construct($email_settings){
						$config = [
							'defaultFrom' => $email_settings['messageFrom'],
							'onError'     => function($error, $message, $transport) { echo $error; },
							'afterSend'   => function($text, $message, $layer) { $nothing = 0; },
							'transports'  => [        
								['smtp', 'host' => $email_settings['smtp'], 'ssl' => true, 'port' => $email_settings['port'], 'login' => $email_settings['login'], 'password' => $email_settings['password']]
							],
						];
						Mailer()->init($config);
						}
								
						public function message_send($messageSubject, $messageFrom, $messageTo, $message_HTML){
							$message = Mailer()->newHtmlMessage();

							$message->setSubject($messageSubject);
							$message->setSenderEmail($messageFrom);
							$message->addRecipient($messageTo);
							$message->addContent($message_HTML);
							
							Mailer()->sendMessage($message);
						}
					}
					
					$email = new email($email_settings);
					$messageFrom = $email_settings['messageFrom'];
					$messageTo = $login;
					
					$replaceArray = array(
						'$messageTo' => $messageTo,
						'$link' => $auth_link,
						'$ip' => $user_ip
					);
					$auth_email_HTML = strtr($NewIPEmail, $replaceArray);
					
					$email->message_send($messageNewIPSubject, $messageFrom, $messageTo, $auth_email_HTML);
					
					$login_db->setLastSID($log_user_id, $session_id);
					
					$return = array(
						'result' => 'OK',
						'description' => 'emailVerificationNeeded'
					);
					
					echo(json_encode($return));
					
				
				// ---
			}
		}
		else{
			returnError('WRONG_CREDENTIALS');
		}
	}
	
	if($method == 'emailIPValidation'){
		$user_ip = $_SERVER['REMOTE_ADDR'];
		$rand_session_id = $_GET['rand_session_id'];
		$session_id = $_GET['session_id'];
		$timestamp = $_GET['timestamp'];
		$login = $_GET['login'];
		$password_token = $_GET['password_hash'];
		$email_ver_id = $_GET['email_ver_id'];
		
		$verification = array(
			'session_ver' => false,
			'timestamp' => false,
			'password' => false,
			'email_ver_id' => false			
		);
		
		//session verification
			$true_session_id = hash('sha256', $rand_session_id . "_" . $timestamp . "_" . $user_ip . "_" . $service_key);
			
			if($session_id == $session_id){
				$verification['session_ver'] = true;
			}
			else{
				returnError('WRONG_SESSION');
			}
		// ---
	
		
		//timestamp verification
			
			if($timestamp + 900 >= time()){
				$verification['timestamp'] = true;
			}
			else{
				returnError('THIS_SESSION_IS_EXPIRED');
			}
		// ---
		
		//password verification
		
			$log_user_id = $login_db->getUIDByEMail($login);
			if(is_int($log_user_id)){
				$user_info = $login_db->get_user_info($log_user_id);
				$true_password_hash = hash('sha256', $user_info['password_hash'] . '_' . $session_id . '_' . $user_ip . '_' . $timestamp . '_' . $rand_session_id . '_' . $login);
				if($true_password_hash == $password_token){
					$verification['password'] = true;
				}
				else{
					returnError('WRONG_CREDENTIALS');
				}
				
				$true_email_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $session_id . '_' . $user_info['SLID']);
				
				if($true_email_ver_id == $email_ver_id){
					$verification['email_ver_id'] = true;
				}
				else{
					returnError('INVALID_VERIFICATION_CODE');
				}
			}
			else{
				returnError('WRONG_CREDENTIALS');
			}
			
		// ---
		
		if($verification['password'] && $verification['timestamp'] && $verification['session_ver'] && $verification['email_ver_id']){
			$last_sid = $login_db->getLastSID($log_user_id);
			if($last_sid == $session_id){
				setcookie("user_id", $log_user_id, time() + 2678400, $domain_name);
				setcookie("email", $login, time() + 2678400, $domain_name);
				setcookie("user_ip", $_SERVER['REMOTE_ADDR'], time() + 2678400, $domain_name);
				setcookie("user_verkey", hash("sha512", "{$session_id}_{$login}_{$log_user_id}_{$user_info['SLID']}_{$_SERVER['REMOTE_ADDR']}_{$service_key}"), time() + 2678400, $domain_name);
				setcookie("session", $session_id, time() + 2678400, $domain_name);
				setcookie("SLID", $user_info['SLID'], time() + 2678400, $domain_name);
				
				$login_db->set_current_user_ip($log_user_id, $_SERVER['REMOTE_ADDR']);
				$login_db->clearLastSID($log_user_id);
				
				$return = array(
					'result' => 'OK',
					'description' => 'Success'
				);
						
				echo(json_encode($return));
			}
			else{
				returnError('UNAUTHORIZED_REQUEST');
			}
		}
	}
	
	if($method == 'send_register_message'){
		$login = $_REQUEST['login'];
		if(!filter_var($login, FILTER_VALIDATE_EMAIL)){
			returnError("INVALID_EMAIL");
		}
		$password_hash = $_REQUEST['password_hash'];
		
		if(!$login_db->wasEmailRegistered($login)){
			$timestamp = time();
			$rsid = bin2hex(random_bytes($session_length / 2));
			$session_id = hash('sha256', $rsid . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);
			$encrypted_password_hash = safe_encrypt($password_hash, $encryption_key);
			setcookie("register_password", $encrypted_password_hash, $timestamp + 900, $domain_name);
			setcookie("register_verify", hash("sha256", $encrypted_password_hash . "_" . $service_key  . "_" . $session_id), $timestamp + 900, $domain_name);
			
			$email_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $password_hash . '_' . $timestamp . "_" . $session_id);
				
			$auth_link = $login_site . "/auth_manager.php?method=registerNewUser&timestamp=$timestamp&login=$login&email_ver_id=$email_ver_id&session_id=$session_id&rand_session_id=$rsid";
			
			require_once 'libs/apmailer.php';
		
			class email{
				public function __construct($email_settings){
					$config = [
						'defaultFrom' => $email_settings['messageFrom'],
						'onError'     => function($error, $message, $transport) { echo $error; },
						'afterSend'   => function($text, $message, $layer) { $nothing = 0; },
						'transports'  => [        
							['smtp', 'host' => $email_settings['smtp'], 'ssl' => true, 'port' => $email_settings['port'], 'login' => $email_settings['login'], 'password' => $email_settings['password']]
						],
					];
					Mailer()->init($config);
				}
								
				public function message_send($messageSubject, $messageFrom, $messageTo, $message_HTML){
					$message = Mailer()->newHtmlMessage();

					$message->setSubject($messageSubject);
					$message->setSenderEmail($messageFrom);
					$message->addRecipient($messageTo);
					$message->addContent($message_HTML);
							
					Mailer()->sendMessage($message);
				}
			}
					
			$email = new email($email_settings);
			$messageFrom = $email_settings['messageFrom'];
			$messageTo = $login;
					
			$replaceArray = array(
				'$messageTo' => $messageTo,
				'$link' => $auth_link,
				'$ip' => $user_ip
			);
			$auth_email_HTML = strtr($registerEmail, $replaceArray);
					
			$email->message_send($messageRegisterSubject, $messageFrom, $messageTo, $auth_email_HTML);
					
			$return = array(
				'result' => 'OK',
				'description' => 'emailVerificationNeeded'
			);
					
			echo(json_encode($return));
		}
		else{
			$return = array(
				'result' => 'OK',
				'description' => 'emailVerificationNeeded'
			);
					
			echo(json_encode($return));
		}
	}
	
	if($method == "registerNewUser"){
		$timestamp = $_GET['timestamp'];
		$login = $_GET['login'];
		$email_ver_id = $_GET['email_ver_id'];
		$session_id = $_GET['session_id'];
		$rand_session_id = $_GET['rand_session_id'];
		$password_hash = $_COOKIE['register_password'];
		$register_verify = $_COOKIE['register_verify'];
		
		if($timestamp + 900 >= time()){
			if(!$login_db->wasEmailRegistered($login)){
				$true_session_id = hash('sha256', $rand_session_id . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);
				if($true_session_id == $session_id){
					$true_register_verify = hash("sha256", $password_hash . "_" . $service_key  . "_" . $session_id);
					if($true_register_verify == $register_verify){
						$real_password_hash = safe_decrypt($password_hash, $encryption_key);			
						if($real_password_hash !== False){
							$true_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $real_password_hash . '_' . $timestamp . "_" . $session_id);
							if($true_ver_id == $email_ver_id){
								$user_id = $login_db->create_new_user($login, $real_password_hash);
								$login_db->set_current_user_ip($user_id, $_SERVER['REMOTE_ADDR']);
								$login_db->regenerateSLID($user_id);
								$login_db->regenerateAPIKey($user_id);
								$user_info = $login_db->get_user_info($user_id);
								
								setcookie('register_password', '', 0, '/');
								setcookie('register_verify', '', 0, '/');
								
								setcookie("user_id", $user_id, time() + 2678400, $domain_name);
								setcookie("email", $login, time() + 2678400, $domain_name);
								setcookie("user_ip", $_SERVER['REMOTE_ADDR'], time() + 2678400, $domain_name);
								setcookie("user_verkey", hash("sha512", "{$session_id}_{$login}_{$user_id}_{$user_info['SLID']}_{$_SERVER['REMOTE_ADDR']}_{$service_key}"), time() + 2678400, $domain_name);
								setcookie("session", $session_id, time() + 2678400, $domain_name);
								setcookie("SLID", $user_info['SLID'], time() + 2678400, $domain_name);
								
								$login_db->set_current_user_ip($log_user_id, $_SERVER['REMOTE_ADDR']);
								
								$return = array(
									'result' => 'OK',
									'description' => 'Success'
								);
								echo(json_encode($return));
							}
							else{
								returnError("UNABLE_TO_CREATE_ACCOUNT");
							}
						}
						else{
							returnError("UNABLE_TO_CREATE_ACCOUNT");
						}
					}
					else{
						returnError("UNABLE_TO_CREATE_ACCOUNT");
					}
				}
				else{
					returnError("UNABLE_TO_CREATE_ACCOUNT");
				}
			}
			else{
				returnError("UNABLE_TO_CREATE_ACCOUNT");
			}
		}
		else{
			returnError("UNABLE_TO_CREATE_ACCOUNT");
		}
	}
	
	if($method == 'send_restore_email'){
		$login = $_REQUEST['login'];
		if(!filter_var($login, FILTER_VALIDATE_EMAIL)){
			returnError("INVALID_EMAIL");
		}
		
		if($login_db->wasEmailRegistered($login)){
			$timestamp = time();
			$rsid = bin2hex(random_bytes($session_length / 2));
			$session_id = hash('sha256', $rsid . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);
			
			$log_user_id = $login_db->getUIDByEMail($login);
			$user_info = $login_db->get_user_info($log_user_id);
			$email_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $timestamp . "_" . $user_info['SLID'] . "_" . $session_id);
				
			$auth_link = $login_site . "/auth_manager.php?method=restorePassword&timestamp=$timestamp&login=$login&email_ver_id=$email_ver_id&rand_session_id=$rsid&session_id=$session_id";
					
			require_once 'libs/apmailer.php';
		
			class email{
				public function __construct($email_settings){
					$config = [
						'defaultFrom' => $email_settings['messageFrom'],
						'onError'     => function($error, $message, $transport) { echo $error; },
						'afterSend'   => function($text, $message, $layer) { $nothing = 0; },
						'transports'  => [        
							['smtp', 'host' => $email_settings['smtp'], 'ssl' => true, 'port' => $email_settings['port'], 'login' => $email_settings['login'], 'password' => $email_settings['password']]
						],
					];
					Mailer()->init($config);
				}
								
				public function message_send($messageSubject, $messageFrom, $messageTo, $message_HTML){
					$message = Mailer()->newHtmlMessage();

					$message->setSubject($messageSubject);
					$message->setSenderEmail($messageFrom);
					$message->addRecipient($messageTo);
					$message->addContent($message_HTML);
							
					Mailer()->sendMessage($message);
				}
			}
					
			$email = new email($email_settings);
			$messageFrom = $email_settings['messageFrom'];
			$messageTo = $login;
					
			$replaceArray = array(
				'$messageTo' => $messageTo,
				'$link' => $auth_link,
				'$ip' => $user_ip
			);
			$auth_email_HTML = strtr($restorePasswordEmail, $replaceArray);
					
			$email->message_send($messageRestoreSubject, $messageFrom, $messageTo, $auth_email_HTML);
			
			$login_db->setLastSID($log_user_id, $session_id);
					
			$return = array(
				'result' => 'OK',
				'description' => 'emailVerificationNeeded'
			);
					
			echo(json_encode($return));
		}
		else{
			$return = array(
				'result' => 'OK',
				'description' => 'emailVerificationNeeded'
			);
					
			echo(json_encode($return));
		}
	}
	if($method == "restorePassword"){
		$timestamp = $_GET['timestamp'];
		$login = $_GET['login'];
		$email_ver_id = $_GET['email_ver_id'];
		$session_id = $_GET['session_id'];
		$rand_session_id = $_GET['rand_session_id'];
		$new_password = $_COOKIE['restore_password'];
		
		if(!isset($new_password)){
			returnError("PASSWORD_IS_MISSING");
		}
		else{
			$log_user_id = $login_db->getUIDByEMail($login);
			$user_info = $login_db->get_user_info($log_user_id);
			
			$true_session_id = hash('sha256', $rand_session_id . "_" . $timestamp . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $service_key);
			$true_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $timestamp . "_" . $user_info['SLID'] . "_" . $session_id);
			$last_sid = $login_db->getLastSID($log_user_id);
			
			if($true_ver_id == $email_ver_id && $timestamp + 900 > time()){
				if($session_id == $true_session_id){
					if($last_sid == $session_id){
						if($login_db->wasEmailRegistered($login)){
							$login_db->changeUserPassword($user_info['user_id'], hash('sha256', $new_password));
							
							setcookie('restore_passwword', '', 0, '/');
							$login_db->clearLastSID($log_user_id);
							
							setcookie("user_id", $log_user_id, time() + 2678400, $domain_name);
							setcookie("email", $login, time() + 2678400, $domain_name);
							setcookie("user_ip", $_SERVER['REMOTE_ADDR'], time() + 2678400, $domain_name);
							setcookie("user_verkey", hash("sha512", "{$session_id}_{$login}_{$log_user_id}_{$user_info['SLID']}_{$_SERVER['REMOTE_ADDR']}_{$service_key}"), time() + 2678400, $domain_name);
							setcookie("session", $session_id, time() + 2678400, $domain_name);
							setcookie("SLID", $user_info['SLID'], time() + 2678400, $domain_name);
							
							$return = array(
								'result' => 'OK',
								'description' => 'Success'
							);
									
							echo(json_encode($return));
						}
						else{
							returnError("UNABLE_TO_CHANGE_PASSWORD1");
						}
					}
					else{
						returnError("UNABLE_TO_CHANGE_PASSWORD2");
					}
				}
				else{
					returnError("UNABLE_TO_CHANGE_PASSWORD3");
				}
			}
			else{
				returnError("UNABLE_TO_CHANGE_PASSWORD4");
			}
		}
	}
	
	if($method == "checkTOTP"){
		$user_id = $_COOKIE['user_id'];
		$SLID = $_COOKIE['SLID'];
		$email = $_COOKIE['email'];
		$session = $_COOKIE['session'];
		$user_ip = $_COOKIE['user_ip'];
		$user_key = $_COOKIE['user_verkey'];
		$otp = $_GET['otp'];
		
		$verified = false;
		
		$ver_user_info = $login_db->get_user_info($user_id);
		if($ver_user_info['user_id'] == $user_id && $ver_user_info['user_id'] != null){
			if($ver_user_info['SLID'] == $SLID){
				if($user_ip == $_SERVER['REMOTE_ADDR']){
					$true_hash = hash("sha512", "{$session}_{$email}_{$user_id}_{$SLID}_{$_SERVER['REMOTE_ADDR']}_{$service_key}");
					
					if($true_hash == $user_key){
						$verified = true;
					}
				}
			}
		}
		
		if($verified){
			$user_info = $login_db->get_user_info($user_id);
			if($user_info['user_id'] == $user_id && $user_id != ""){				
				$totp_instance = new Totp();
				$base32 = new Base32();
				
				$secret = $user_info['2fa_secret'];
				$secret = $base32->decode($secret);
				
				$key = $totp_instance->GenerateToken($secret);
				
				if($otp == $key){
					$totp_timestamp = time();
					$true_totp_ver = hash("sha512", "{$SLID}_{$ver_user_info['2fa_secret']}_{$ver_user_info['user_id']}_{$totp_timestamp}");
					
					setcookie("totp_timestamp", $totp_timestamp, time() + 2678400, $domain_name);
					setcookie("totp_verification", $true_totp_ver, time() + 2678400, $domain_name);
				}
			}
		}
	}
	
	if($method == "disable_totp"){
		$user_id = $_COOKIE['user_id'];
		$SLID = $_COOKIE['SLID'];
		$email = $_COOKIE['email'];
		$session = $_COOKIE['session'];
		$user_ip = $_COOKIE['user_ip'];
		$user_key = $_COOKIE['user_verkey'];
		$key = $_GET['key'];
		
		$verified = false;
		
		$ver_user_info = $login_db->get_user_info($user_id);
		if($ver_user_info['user_id'] == $user_id && $ver_user_info['user_id'] != null){
			if($ver_user_info['SLID'] == $SLID){
				if($user_ip == $_SERVER['REMOTE_ADDR']){
					$true_hash = hash("sha512", "{$session}_{$email}_{$user_id}_{$SLID}_{$_SERVER['REMOTE_ADDR']}_{$service_key}");
					
					if($true_hash == $user_key){
						$verified = true;
					}
				}
			}
		}
		
		if($verified){
			$user_info = $login_db->get_user_info($user_id);
			if($user_info['user_id'] == $user_id && $user_id != ""){
				$hash_code = hash('sha256', $key . "_" . $user_id);
				if($hash_code == $user_info['2fa_disable_code']){
					$login_db->disable_totp($user_id);
					$return = array(
						'result' => "OK",
						'description' => "Success"
					);
					
					echo(json_encode($return));
				}
				else{
					returnError("WRONG_DISABLE_KEY");
				}
			}
		}
	}
	
	if($method == "el_getSession"){
		$session = "session_" . convBase(uniqidReal(256), 16, 36);
		$sess_salt = convBase(uniqidReal(32), 16, 36);
		$login_db->create_session($session, $sess_salt, $_SERVER['REMOTE_ADDR']);
		
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
	}
	
	if($method == "el_removeSession"){
		$session = $login_db->get_session($_GET['session_id']);
		
		if($session['session'] != ''){
			$true_sess_ver = hash("sha256", $session['session'] . "_" . $service_key . "_" . $session['session_seed'] . "_" . $_SERVER['REMOTE_ADDR']);
			
			if($true_sess_ver == $_GET['session_ver']){
				$login_db->delete_session($session['session']);
				$return = array(
					'result' => "OK",
					'description' => "Success"
				);
							
				echo(json_encode($return));
			}
			else{
				returnError("UNAUTHORIZED");
			}
		}
		else{
			returnError("WRONG_SESSION");
		}
	}
	
	if($method == "el_checkSession"){
		$session = $login_db->get_session($_GET['session_id']);
		
		if($session['session'] != ''){
			$true_sess_ver = hash("sha256", $session['session'] . "_" . $service_key . "_" . $session['session_seed'] . "_" . $_SERVER['REMOTE_ADDR']);
			
			if($true_sess_ver == $_GET['session_ver']){
				if($session['claimed'] == 1){
					if($session['created'] + 300 >= time()){						
						$user_info = $login_db->get_user_info($session['user_id']);
						if($user_info['easylogin'] == 1){
							if($_SERVER['REMOTE_ADDR'] == $session['ip']){
								$rsid = bin2hex(random_bytes($session_length / 2));
								$timestamp = time();
								
								$login_db->set_current_user_ip($user_info['user_id'], $_SERVER['REMOTE_ADDR']);
								
								$login_db->delete_session($session['session']);
								
								setcookie("user_id", $user_info['user_id'], time() + 2678400, $domain_name);
								setcookie("email", $user_info['user_email'], time() + 2678400, $domain_name);
								setcookie("user_ip", $_SERVER['REMOTE_ADDR'], time() + 2678400, $domain_name);
								setcookie("user_verkey", hash("sha512", "{$rsid}_{$user_info['user_email']}_{$user_info['user_id']}_{$user_info['SLID']}_{$_SERVER['REMOTE_ADDR']}_{$service_key}"), time() + 2678400, $domain_name);
								setcookie("session", $rsid, time() + 2678400, $domain_name);
								setcookie("SLID", $user_info['SLID'], time() + 2678400, $domain_name);
								
								$return = array(
									'result' => 'OK',
									'description' => 'Success'
								);
								
								echo(json_encode($return));
							}
							else{
								returnError("UNKNOWN_IP");
							}
						}
						else{
							returnError("THIS_FEATURE_WAS_DISABLED_BY_OWNER");
						}
					}
					else{
						returnError("TIMEOUT");
					}
				}
				else{
					returnError("UNCLAIMED");
				}
			}
			else{
				returnError("UNAUTHORIZED");
			}
		}
		else{
			returnError("WRONG_SESSION");
		}
	}
	
	if($method == "checkIDToken"){
		$project_secret = $_GET['secret'];
		$project = $login_db->getProjectInfoBySecret($project_secret);
		
		if($project['project_id'] != ""){
			$id_token = $_GET['id_token'];
			$user_id = $_GET['user_id'];
			
			$test_uinfo = $login_db->get_user_info($user_id);
			if($test_uinfo['user_email'] != ""){
				$true_token = hash('sha512', $test_uinfo['user_id'] . "_" . $test_uinfo['user_email'] . "_" . $test_uinfo['password_hash'] . "_" . $test_uinfo['api_key_seed'] . "_" . $test_uinfo['SLID'] . "_" . $test_uinfo['2fa_secret'] . "_" . $project['secret_key']);
				
				if($true_token == $id_token){
					$return = array(
						'result' => "OK",
						'description' => "VALID",
						'uls_id' => $test_uinfo['user_id']
					);
					echo(json_encode($return));
				}
				else{
					returnError("INVALID_TOKEN");
				}
			}
			else{
				returnError("INVALID_USER");
			}
		}
	}
}
else{
	$access_token = $_REQUEST['access_token'];
	$ate = explode(":", $access_token);
	$user_id = $ate[0];
	$uinfo = $login_db->get_user_info($user_id);
	if($uinfo['user_id'] == null || $uinfo['user_id'] != $user_id){
		returnError("ACCESS_TOKEN_IS_NOT_VALID");
	}
	$token_main_part = hash('sha512', $service_key . $user_id . $uinfo['api_key_seed']);
	if($token_main_part == $ate[1]){
		$verified = true;
	}
	else{
		returnError("ACCESS_TOKEN_IS_NOT_VALID");
	}
	
	if($verified){
		if($section == "projects"){
			if($method == "login"){
				$project_public = $_GET['public'];
				$project = $login_db->getProjectInfoByPublic($project_public);
				
				if($project['project_id'] == ""){
					returnError("UNKNOWN_PROJECT");
				}
				
				$login_db->updateProjectLastUsed($project['project_id']);
				
				$timestamp = time();
				$session = hash('sha256', $uinfo['user_id'] . "_" . $project['secret_key'] . "_" . bin2hex(random_bytes(32)) . "_" . $timestamp);
				
				$id_token = hash('sha512', $uinfo['user_id'] . "_" . $uinfo['user_email'] . "_" . $uinfo['password_hash'] . "_" . $uinfo['api_key_seed'] . "_" . $uinfo['SLID'] . "_" . $uinfo['2fa_secret'] . "_" . $project['secret_key']);
				
				$ver_code = hash('sha512', $uinfo['user_id'] . "_" . $_SERVER['REMOTE_ADDR'] . "_" . $session . "_" . $timestamp . "_" . $id_token . "_" . $project['secret_key']);
				
				if(strpos($project['redirect_uri'], "?") !== false){
					$params = "&";
				}
				else{
					$params = "?";
				}
				
				$request_params = array(
					'uls_id' => $uinfo['user_id'],
					'session' => $session,
					'timestamp' => $timestamp,
					'user_token' => $id_token,
					'sign' => $ver_code
				);

				$params .= http_build_query($request_params);
				
				$redirect_url = $project['redirect_uri'] . $params;
				
				$return = array(
					'result' => "OK",
					'redirect' => $redirect_url
				);
				echo(json_encode($return));
			}
		}
		if($section == "users"){
			if($method == "getCurrentEmail"){
				$email = $uinfo['user_email'];
				
				$return = array(
					'result' => "OK",
					'email' => $email
				);
				echo(json_encode($return));
			}
			
			if($method == "logout"){
				setcookie('user_verkey', '', 0, $domain_name);
				setcookie('user_ip', '', 0, $domain_name);
				setcookie('session', '', 0, $domain_name);
				setcookie('email', '', 0, $domain_name);
				setcookie('SLID', '', 0, $domain_name);
				setcookie('user_id', '', 0, $domain_name);
				setcookie('totp_verification', '', 0, $domain_name);
				setcookie('totp_timestamp', '', 0, $domain_name);
			}
			
			if($method == "regenerate_api_key"){
				$login_db->regenerateAPIKey($user_id);
			}
			
			if($method == "regenerate_slid"){
				$login_db->regenerateSLID($user_id);
			}
			
			if($method == "changeUserPassword"){
				$password_hash = hash('sha256', $_GET['password']);
				$login_db->changeUserPassword($user_id, $password_hash);
			}
			
			if($method == "changeUserEmail"){
				$new_email = $_GET['email'];
				if($new_email != $uinfo['user_email']){
					if(filter_var($new_email, FILTER_VALIDATE_EMAIL)){
						if(!$login_db->wasEmailRegistered($new_email)){
							$login_db->changeUserEmail($user_id, $new_email);
						}
					}
					else{
						returnError("GIVEN_EMAIL_IS_INVALID");
					}
				}
				else{
					returnError("YOU_ARE_CURRENTLY_USING_THIS_EMAIL");
				}
			}
		}
		
		if($section == "totp"){
			if($method == "get2FAInfo"){
				$return = array(
					'result' => "OK",
					'totp_active' => $uinfo['2fa_active']
				);
				echo(json_encode($return));
			}
			
			if($method == "prepare_enable"){
				if($uinfo['2fa_active'] == 0){
					$first_name = "DS Software ULS";
					$email = $uinfo['user_email'];
					
					$totp_instance = new Totp();
					$base32 = new Base32();

					$secret = $totp_instance->GenerateSecret(16);
					$true_secret = $base32->encode($secret);
					
					$login_db->set_totp_secret($user_id, $true_secret);
					
					$totp_url = "/gen_2fa_qr.php?fn={$first_name}&email={$email}&secret={$true_secret}";
					
					$return = array(
						'result' => "OK",
						'url' => $totp_url,
						'secret' => $true_secret
					);
					echo(json_encode($return));
				}
				else{
					returnError("TOTP_WAS_ENABLED_BEFORE");
				}
			}
			if($method == "enable"){
				if($uinfo['2fa_active'] == 0){
					$otp = $_REQUEST['otp'];
					$totp_instance = new Totp();
					$base32 = new Base32();

					$secret = $uinfo['2fa_secret'];
					$secret = $base32->decode($secret);
					
					$key = $totp_instance->GenerateToken($secret);
					
					if($key == $otp){
						$dis_code = convBase(uniqidReal(20), 16, 36);
						
						$login_db->enable_totp($user_id);
						$login_db->set_TOTP_disable_code($user_id, $dis_code);
						
						$return = array(
							'result' => "OK",
							'description' => 'Success',
							'disableCode' => $dis_code
						);
						echo(json_encode($return));
					}
					else{
						returnError("WRONG_TOTP");
					}
				}
				else{
					returnError("TOTP_WAS_ENABLED_BEFORE");
				}
			}
			if($method == "disable"){
				if($uinfo['2fa_active'] == 1){
					$otp = $_REQUEST['otp'];
					$totp_instance = new Totp();
					$base32 = new Base32();

					$secret = $uinfo['2fa_secret'];
					$secret = $base32->decode($secret);
					
					$key = $totp_instance->GenerateToken($secret);
					
					if($key == $otp){		
						$login_db->disable_totp($user_id);
						
						$return = array(
							'result' => "OK",
							'description' => 'Success'
						);
						echo(json_encode($return));
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
		
		if($section == "easylogin"){
			if($method == "getEasyLoginInfo"){
				$return = array(
					'result' => "OK",
					'easylogin_active' => $uinfo['easylogin']
				);
				echo(json_encode($return));
			}
			
			if($method == "enable"){
				$login_db->enable_el($user_id);
				
				$return = array(
					'result' => "OK",
					'desc' => 'Success'
				);
				echo(json_encode($return));
			}
			
			if($method == "disable"){
				$login_db->disable_el($user_id);
				
				$return = array(
					'result' => "OK",
					'desc' => 'Success'
				);
				echo(json_encode($return));
			}
			
			if($method == "claim"){
				$session = $login_db->get_session($_GET['session_id']);
				
				if($session['session'] != ''){
					$true_sess_ver = hash("sha256", $session['session'] . "_" . $service_key . "_" . $session['session_seed'] . "_" . $session['ip']);
					
					if($true_sess_ver == $_GET['session_ver']){
						if($session['created'] + 300 >= time()){
							$user_info = $login_db->get_user_info($user_id);
							if($user_info['easylogin'] == 1){
								if($user_info['2fa_active'] == 1){
									$login_db->claim_session($user_id, $session['session']);
									
									$return = array(
										'result' => "OK",
										'desc' => 'Success'
									);
									echo(json_encode($return));
								}
								else{
									returnError("2FA_DISABLED");
								}
							}
							else{
								returnError("THIS_FEATURE_WAS_DISABLED_BY_OWNER");
							}
						}
						else{
							$login_db->delete_session($session['session']);
							returnError("TIMEOUT");
						}
					}
					else{
						returnError("UNAUTHORIZED");
					}
				}
				else{
					returnError("WRONG_SESSION");
				}
			}
		}
		
		if($section == "integration"){
			if($method == "getUserProjects"){
				$projects = $login_db->getUserProjects($user_id);
				$login_db->cleanUpProjects($delete_projects_on_inactivity, $deletion_timeout);
				
				$return = array(
					'result' => "OK",
					'projects' => $projects
				);
				echo(json_encode($return));
			}
			if($method == "createProject"){
				if(strlen($_GET['name']) < 3 OR strlen($_GET['name']) > 32){
					returnError("TOO_LONG_OR_TOO_SHORT");
				}
				else{
					$login_db->createProject($user_id, htmlentities($_GET['name']));
					
					$return = array(
						'result' => "OK"
					);
					echo(json_encode($return));
				}
			}
			if($method == "getProjectInfo"){
				$project = $login_db->getProjectInfo($_GET['project']);
				$login_db->cleanUpProjects($delete_projects_on_inactivity, $deletion_timeout);
				if($project['owner_id'] != $user_id){
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
			}
			
			if($method == "issueNewPublic"){
				$project = $login_db->getProjectInfo($_GET['project']);
				$login_db->cleanUpProjects($delete_projects_on_inactivity, $deletion_timeout);
				if($project['owner_id'] != $user_id){
					returnError("UNAUTHORIZED");
				}
				$login_db->regenerateProjectPublic($project['project_id']);
				$return = array(
					'result' => "OK"
				);
				echo(json_encode($return));
			}
			
			if($method == "issueNewSecret"){
				$project = $login_db->getProjectInfo($_GET['project']);
				$login_db->cleanUpProjects($delete_projects_on_inactivity, $deletion_timeout);
				if($project['owner_id'] != $user_id){
					returnError("UNAUTHORIZED");
				}
				$login_db->regenerateProjectSecret($project['project_id']);
				$return = array(
					'result' => "OK"
				);
				echo(json_encode($return));
			}
			
			if($method == "changeRedirect"){
				$project = $login_db->getProjectInfo($_GET['project']);
				$login_db->cleanUpProjects($delete_projects_on_inactivity, $deletion_timeout);
				if($project['owner_id'] != $user_id){
					returnError("UNAUTHORIZED");
				}
				$login_db->changeRedirectURL($project['project_id'], $_GET['redirect_url']);
				$return = array(
					'result' => "OK"
				);
				echo(json_encode($return));
			}
			
			if($method == "changeName"){
				$project = $login_db->getProjectInfo($_GET['project']);
				$login_db->cleanUpProjects($delete_projects_on_inactivity, $deletion_timeout);
				if($project['owner_id'] != $user_id){
					returnError("UNAUTHORIZED");
				}
				if(strlen($_GET['name']) < 3 OR strlen($_GET['name']) > 32){
					returnError("TOO_LONG_OR_TOO_SHORT");
				}
				else{
					$login_db->changeProjectName($project['project_id'], htmlentities($_GET['name']));
					
					$return = array(
						'result' => "OK"
					);
					echo(json_encode($return));
				}
			}
			if($method == "delete"){
				$project = $login_db->getProjectInfo($_GET['project']);
				$login_db->cleanUpProjects($delete_projects_on_inactivity, $deletion_timeout);
				if($project['owner_id'] != $user_id){
					returnError("UNAUTHORIZED");
				}
				$login_db->deleteProject($project['project_id']);
			}
		}
	}
}

?>