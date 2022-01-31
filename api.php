<?php
require_once 'config.php';
require_once 'database.php';
require_once 'email_templates.php';
require_once 'encryption.php';
require_once "libs/Base32.php";
require_once "libs/Hotp.php";
require_once "libs/Totp.php";
require_once "libs/browser_libs.php";

use lfkeitel\phptotp\{Base32,Totp};

if (isset($_SERVER['HTTP_ORIGIN'])) {
    if(in_array($_SERVER['HTTP_ORIGIN'], $allowed_origins)){
		header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
		header('Access-Control-Allow-Credentials: true');
		header('Access-Control-Max-Age: 86400');
	}
}

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
				
					$auth_link = $login_site . "/api.php?section=UNAUTH&method=emailIPValidation&rand_session_id=$rand_session_id&session_id=$session_id&timestamp=$timestamp&login=$login&password_hash=$password_token&email_ver_id=$email_ver_id";
					
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
			setcookie("user_id", $log_user_id, time() + 2678400, $domain_name);
			setcookie("email", $login, time() + 2678400, $domain_name);
			setcookie("user_ip", $_SERVER['REMOTE_ADDR'], time() + 2678400, $domain_name);
			setcookie("user_verkey", hash("sha512", "{$session_id}_{$login}_{$log_user_id}_{$user_info['SLID']}_{$_SERVER['REMOTE_ADDR']}_{$service_key}"), time() + 2678400, $domain_name);
			setcookie("session", $session_id, time() + 2678400, $domain_name);
			setcookie("SLID", $user_info['SLID'], time() + 2678400, $domain_name);
			
			$login_db->set_current_user_ip($log_user_id, $_SERVER['REMOTE_ADDR']);
			
			$return = array(
				'result' => 'OK',
				'description' => 'Success'
			);
					
			echo(json_encode($return));
			header("Location: $login_site");
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
			$encrypted_password_hash = safe_encrypt($password_hash, $encryption_key);
			$email_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $password_hash . '_' . $timestamp);
				
			$auth_link = $login_site . "/api.php?section=UNAUTH&method=register_new_user" .  '&ts=' . "$timestamp&login=$login&password_hash=$encrypted_password_hash&email_ver_id=$email_ver_id";			
			
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
	
	if($method == "register_new_user"){
		$timestamp = $_GET['ts'];
		$login = $_GET['login'];
		$password_hash = $_GET['password_hash'];
		$email_ver_id = $_GET['email_ver_id'];
		
		if($timestamp + 900 >= time()){
			if(!$login_db->wasEmailRegistered($login)){
				$real_password_hash = safe_decrypt($password_hash, $encryption_key);			
				if($real_password_hash !== False){
					$true_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $real_password_hash . '_' . $timestamp);
					if($true_ver_id == $email_ver_id){
						$user_id = $login_db->create_new_user($login, $real_password_hash);
						$login_db->set_current_user_ip($user_id, $_SERVER['REMOTE_ADDR']);
						$login_db->regenerateSLID($user_id);
						$login_db->regenerateAPIKey($user_id);
						header("Location: $login_site");
					}
					else{
						header("Location: $login_site?error=INVALID_LINK");
					}
				}
				else{
					header("Location: $login_site?error=PASSWORD_CORRUPTED");
				}
			}
			else{
				header("Location: $login_site?error=EMAIL_WAS_TAKEN");
			}
		}
		else{
			header("Location: $login_site?error=EXPIRED_LINK");
		}
	}
	
	if($method == 'send_restore_email'){
		$login = $_REQUEST['login'];
		if(!filter_var($login, FILTER_VALIDATE_EMAIL)){
			returnError("INVALID_EMAIL");
		}
		
		if($login_db->wasEmailRegistered($login)){
			$user_info = $login_db->get_user_info($login_db->getUIDByEMail($login));
			$timestamp = time();
			$email_ver_id = hash("sha256", $login . '_' . $service_key . '_' . $timestamp . "_" . $user_info['SLID']);
				
			$auth_link = $login_site . "/api.php?section=UNAUTH&method=restore_password&timestamp=$timestamp&login=$login&email_ver_id=$email_ver_id";
					
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
	if($method == "restore_password"){
		$timestamp = $_GET['timestamp'];
		$login = $_GET['login'];
		$email_ver_id = $_GET['email_ver_id'];
		$new_password = $_REQUEST['new_password'];
		
		if(!isset($new_password)){
			$link = $login_site . "/new_password.php?login={$login}&timestamp={$timestamp}&email_ver_id={$email_ver_id}";
			header("Location: $link");
		}
		else{
			$user_info = $login_db->get_user_info($login_db->getUIDByEMail($login));
			$email_ver_id_true = hash("sha256", $login . '_' . $service_key . '_' . $timestamp . '_' . $user_info['SLID']);
			
			if($email_ver_id_true == $email_ver_id && $timestamp + 900 > time()){
				if($login_db->wasEmailRegistered($login)){
					$login_db->changeUserPassword($user_info['user_id'], hash('sha256', $new_password));
					header("Location: $login_site?state=CHANGED_SUCCESSFULLY");
				}
			}
			else{
				header("Location: $login_site");
			}
		}
	}
	
	if($method == "check_totp"){
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
	
		header("Location: $login_site");
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
				$project = $_GET['project'];
				
				$true_user_id = $uinfo['user_id'];
				$true_user_ip = $_SERVER['REMOTE_ADDR'];
				$true_user_email = $uinfo['user_email'];
				$timestamp = time();
				
				if($projects[$project]['url'] != ""){
					$project_info = $projects[$project];
					
					$project_api = $project_info['api'];
					$project_url = $project_info['url'];
					$project_service_key = $project_info['key'];
					
					$ver_code = hash("sha512", "{$true_user_id}_{$true_user_ip}_{$true_user_email}_{$timestamp}_{$project_service_key}");
					
					$request_params = array(
						'section' => "UNAUTH",
						'method' => "loginViaULS",
						'uls_id' => $true_user_id,
						'user_ip' => $true_user_ip,
						'user_email' => $true_user_email,
						'timestamp' => $timestamp,
						'verification_code' => $ver_code
					);

					$get_params = http_build_query($request_params);

					$final_url = $project_api . "?" . $get_params;
					
					$return = array(
						'result' => "OK",
						'url' => $final_url
					);
					
					echo(json_encode($return));
				}
				else{
					returnError("WRONG_OR_UNCONFIGURED_PROJECT");
				}
			}
			
			if($method == "getUserValidationCode"){
				$user_id = $_COOKIE['user_id'];
				$SLID = $_COOKIE['SLID'];
				$email = $_COOKIE['email'];
				$session = $_COOKIE['session'];
				$user_ip = $_COOKIE['user_ip'];
				$user_key = $_COOKIE['user_verkey'];
				$totp_timestamp = $_COOKIE['totp_timestamp'];
				$totp_verification = $_COOKIE['totp_verification'];
				$true_timestamp = time();
				
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
							'result' => "OK",
							'code' => null,
							'created' => null,
							'verification' => null
						);
						
						echo(json_encode($return, 1));
						die();
					}
				}
				
				if($verified){
					$code = hash("sha512", "{$user_id}_{$SLID}_{$email}_{$session}_{$user_ip}_{$user_key}_{$totp_timestamp}_{$totp_verification}_{$true_timestamp}_{$service_oauth}");
					
					$verification = hash("sha512", "{$user_id}_{$code}_{$service_verification}");
					
					$return = array(
						'result' => "OK",
						'code' => $code,
						'created' => $true_timestamp,
						'verification' => $verification
					);
					echo(json_encode($return));
				}
				else{
					returnError("UNABLE_TO_VERIFY_USER");
				}
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
						else{
							returnError("GIVEN_EMAIL_WAS_REGISTERED");
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
	}
}

?>