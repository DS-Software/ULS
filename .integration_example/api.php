<?php

require_once "config.php";
require_once "database.php";

$database = new database();

$method = $_GET['method'];
$section = $_GET['section'];

function returnError($error){
	$return = array(
		'result' => 'FAULT',
		'reason' => $error
	);

	echo(json_encode($return, 1));
	die();
}

if($section == "UNAUTH"){
	if($method == "login"){
		$uls_id = $_REQUEST['uls_id'];
		$timestamp = $_REQUEST['timestamp'];
		$session = $_REQUEST['session'];
		$token = $_REQUEST['token'];
		$user_info = $_REQUEST['user_info'];
		$sign = $_REQUEST['sign'];

		$user_info_decoded = json_decode(base64_decode($user_info), true);

		$ver_code = hash('sha512', $uls_id . "_" . $timestamp . "_" . $session . "_" . $token . "_" . $user_info . "_" . $project_secret);

		if($ver_code == $sign){
			if($timestamp + 30 >= time()){
				$user_id = $database->getUserIDByULSID($uls_id);
				if($user_id != ""){
					setcookie("user_id", $user_id, time() + 2629743, $domain_name);
					setcookie("uls_id", $uls_id, time() + 2629743, $domain_name);
					setcookie("sign", hash("sha256", "{$session}_{$uls_id}_{$user_id}_{$user_info_decoded['user_ip']}_{$token}_{$secure_key}"), time() + 2629743, $domain_name);
					setcookie("session", $session, time() + 2629743, $domain_name);
					setcookie("token", $token, time() + 2629743, $domain_name);
				}
				else{
					$user_id = $database->createNewUser($uls_id);
				}
			}
		}

		header("Location: $site");
	}
	
	if($method == "getToken"){
		$logged_in = false;

		$user_id = $_COOKIE['user_id'];
		$uls_id = $_COOKIE['uls_id'];
		$session = $_COOKIE['session'];
		$sign = $_COOKIE['sign'];
		$token = $_COOKIE['token'];
		
		$true_sign = hash("sha256", "{$session}_{$uls_id}_{$user_id}_{$_SERVER['REMOTE_ADDR']}_{$token}_{$secure_key}");
	
		if($true_sign == $sign){
			$logged_in = true;
		}
		else{
			returnError("INVALID_SIGN");
		}
		
		if($extended_auth){
			$getUInfo = $login_api . "api.php?section=authentication&method=getUserInfo";

			$curl = curl_init($getUInfo);
			curl_setopt($curl, CURLOPT_URL, $getUInfo);
			curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

			$headers = array(
			   "Accept: application/json",
			   "Authorization: Bearer " . $token
			);
			curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);

			$resp = curl_exec($curl);
			curl_close($curl);
			
			$response = json_decode($resp, true);
			if($response['result'] != "OK" || $response['description'] != "VALID"){
				setcookie('sign', '', 0, $domain_name);
				setcookie('user_id', '', 0, $domain_name);
				setcookie('session', '', 0, $domain_name);
				setcookie('token', '', 0, $domain_name);
				setcookie('uls_id', '', 0, $domain_name);
				returnError("UNABLE_TO_AUTHENTICATE");
			}
		}
		
		if($logged_in){
			$token_seed = bin2hex(random_bytes(32));
			
			$token = array(
				"user_id" => $user_id,
				"seed" => $token_seed,
				"sign" => hash("sha512", "{$user_id}_{$token_seed}_{$secure_key}")
			);
			
			if($response['user_info'] != null){
				$user = json_decode(base64_decode($response['user_info']), 1);
			}
			
			$return = array(
				'result' => 'OK',
				'token' => base64_encode(json_encode($token)),
				'user' => $user
			);
			
			echo(json_encode($return, 1));
		}
	}
}

?>