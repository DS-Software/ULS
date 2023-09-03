<?php

class database{
	
	private $ldb;
	public $success;

	public function __construct($database){
		$login_db = new mysqli($database['hostname'], $database['login'], $database['password'], $database['dbname']);
		if ($login_db->connect_errno) {
			$this->success = false;
			return;
		}
		$this->ldb = $login_db; 
		$this->ldb->set_charset("utf8mb4");
		$this->success = true;
	}

	public function getUserInfo($user_id){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$req = "SELECT `user_id`, `user_nick`, `user_email`, `user_name`, `user_surname`, `birthday`, `verified`, `user_salt`, `password_hash`, `ip_ver_code`, `user_ip`, `api_key_seed`, `SLID`, `last_sid`, `email_check`, `2fa_active`, `2fa_secret`, `2fa_disable_code`, `is_banned`, `ban_reason` FROM `users` WHERE `user_id`='$user_id'";
		$user_id = null;
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($user_id, $user_nick, $user_email, $user_name, $user_surname, $birthday, $verified, $salt, $password_hash, $ip_ver_code, $user_ip, $api_key_seed, $SLID, $last_sid, $email_check, $totp_active, $totp_secret, $totp_disable_code, $is_banned, $ban_reason);
		$statement->fetch();

		$user_object = array(
			'user_id' => $user_id,
			'user_nick' => $user_nick,
			'user_email' => $user_email,
			'user_name' => $user_name,
			'user_surname' => $user_surname,
			'birthday' => $birthday,
			'verified' => $verified,
			'salt' => $salt,
			'password_hash' => $password_hash,
			'ip_ver_code' => $ip_ver_code,
			'user_ip' => $user_ip,
			'api_key_seed' => $api_key_seed,
			'SLID' => $SLID,
			'last_sid' => $last_sid,
			'email_check' => $email_check,
			'2fa_active' => $totp_active,
			'2fa_secret' => $totp_secret,
			'2fa_disable_code' => $totp_disable_code,
			'is_banned' => $is_banned,
			'ban_reason' => $ban_reason
		);

		return $user_object;
	}

	public function isNickUsed($nick){
		$login_db = $this->ldb;
		$nick = $login_db->real_escape_string($nick);
		$req = "SELECT `user_id` FROM `users` WHERE `user_nick`='$nick'";
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($user_id);
		if ($statement->fetch()) {
			return true;
		}
		return false;
	}

	public function saveUserInfo($user_id, $user_nick, $user_name, $user_surname, $birthday){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$user_nick = $login_db->real_escape_string($user_nick);
		$user_name = $login_db->real_escape_string($user_name);
		$user_surname = $login_db->real_escape_string($user_surname);
		$birthday = $login_db->real_escape_string($birthday);

		$req = "UPDATE `users` SET `user_nick`='$user_nick', `user_name`='$user_name', `user_surname`='$user_surname', `birthday`='$birthday' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}

	public function getUIDByEMail($email){
		$login_db = $this->ldb;
		$email = $login_db->real_escape_string($email);
		$req = "SELECT `user_id` FROM `users` WHERE `user_email`='$email'";
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($user_id);
		$statement->fetch();
		return $user_id;
	}

	public function setUserIP($user_id, $ip){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$ip = $login_db->real_escape_string($ip);
		$req = "UPDATE `users` SET `user_ip`='$ip' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}
	
	public function setTOTPState($user_id, $state){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$state = $login_db->real_escape_string($state);
		$req = "UPDATE `users` SET `2fa_active`='$state' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}

	public function setTOTPSecret($user_id, $totp_secret){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$totp_secret = $login_db->real_escape_string($totp_secret);
		$req = "UPDATE `users` SET `2fa_active`=0, `2fa_secret`='$totp_secret' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}

	public function setTOTPDisableCode($user_id, $code){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$hash_code = hash('sha256', $code . "_" . $user_id);
		$req = "UPDATE `users` SET `2fa_disable_code`='$hash_code' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}

	public function createNewUser($email, $password_hash){
		$login_db = $this->ldb;
		$email = $login_db->real_escape_string($email);
		$password_hash = $login_db->real_escape_string($password_hash);
		$req = "INSERT INTO `users`(`user_email`, `password_hash`) VALUES ('$email', '$password_hash')";
		$login_db->query($req);
		return $login_db->insert_id;
	}

	public function regenerateAPIKey($user_id){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$random_uuid = hash('sha256', $user_id . bin2hex(random_bytes(64)) . time());
		$req = "UPDATE `users` SET `api_key_seed`='$random_uuid' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}

	public function regenerateSLID($user_id){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$random_uuid = hash('sha256', $user_id . bin2hex(random_bytes(32)) . time());
		$req = "UPDATE `users` SET `SLID`='$random_uuid' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}

	public function changeUserPassword($user_id, $password_hash){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$password_hash = $login_db->real_escape_string($password_hash);
		$req = "UPDATE `users` SET `password_hash` = '$password_hash' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}

	public function changeUserEmail($user_id, $user_email){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$user_email = $login_db->real_escape_string($user_email);
		$req = "UPDATE `users` SET `user_email` = '$user_email' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}

	public function wasEmailRegistered($user_email){
		$login_db = $this->ldb;
		$user_email = $login_db->real_escape_string($user_email);
		$req = "SELECT `user_id` FROM `users` WHERE `user_email`='$user_email'";
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($user_id);
		if ($statement->fetch()) {
			return true;
		}
		return false;
	}

	public function deleteProject($project_id){
		$login_db = $this->ldb;
		$project_id = $login_db->real_escape_string($project_id);
		$req = "UPDATE `projects` SET `enabled`=0 WHERE `project_id`='$project_id'";
		$login_db->query($req);
	}

	public function getUserProjects($owner_id){
		$login_db = $this->ldb;
		$owner_id = $login_db->real_escape_string($owner_id);
		$req = "SELECT `project_id`, `project_name`, `enabled`, `banned` FROM `projects` WHERE `owner_id`='$owner_id'";
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($project_id, $project_name, $enabled, $banned);
		$projects = [];
		while ($statement->fetch()) {
			$projects[$project_id] = array(
				"project_id" => $project_id,
				"project_name" => $project_name,
				"enabled" => $enabled,
				"banned" => $banned
			);
		}
		return $projects;
	}

	public function countUserProjects($owner_id){
		$login_db = $this->ldb;
		$owner_id = $login_db->real_escape_string($owner_id);
		$req = "SELECT COUNT(*) FROM `projects` WHERE `owner_id`='$owner_id'";
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($amount);
		$statement->fetch();
		return $amount;
	}

	public function getProjectInfo($project_id){
		$login_db = $this->ldb;
		$project_id = $login_db->real_escape_string($project_id);
		$req = "SELECT `project_id`, `project_name`, `redirect_uri`, `secret_key`, `public_key`, `owner_id`, `verified` FROM `projects` WHERE `project_id`='$project_id' AND `enabled`=1 AND `banned`=0";
		$project_id = null;
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($project_id, $project_name, $redirect_uri, $secret_key, $public_key, $owner_id, $verified);
		$statement->fetch();
		
		$project = array(
			"project_id" => $project_id,
			"project_name" => $project_name,
			"redirect_uri" => $redirect_uri,
			"secret_key" => $secret_key,
			"public_key" => $public_key,
			"owner_id" => $owner_id,
			"verified" => $verified
		);
		
		return $project;
	}
	
	public function getAdminProjectInfo($project_id){
		$login_db = $this->ldb;
		$project_id = $login_db->real_escape_string($project_id);
		$req = "SELECT `project_id`, `project_name`, `redirect_uri`, `owner_id`, `verified`, `enabled`, `banned` FROM `projects` WHERE `project_id`='$project_id'";
		$project_id = null;
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($project_id, $project_name, $redirect_uri, $owner_id, $verified, $enabled, $banned);
		$project["exists"] = false;
		if($statement->fetch()){
			$project = array(
				"project_id" => $project_id,
				"project_name" => $project_name,
				"redirect_uri" => $redirect_uri,
				"owner_id" => $owner_id,
				"verified" => $verified,
				"enabled" => $enabled,
				"banned" => $banned,
				"exists" => true
			);
		}
		return $project;
	}
	
	public function adminDeleteProject($project_id){
		$login_db = $this->ldb;
		$project_id = $login_db->real_escape_string($project_id);
		$req = "DELETE FROM `projects` WHERE `project_id`='$project_id'";
		$login_db->query($req);
	}
	
	public function adminRestoreProject($project_id){
		$login_db = $this->ldb;
		$project_id = $login_db->real_escape_string($project_id);
		$req = "UPDATE `projects` SET `enabled`=1 WHERE `project_id`='$project_id'";
		$login_db->query($req);
	}
	
	public function adminVerifyProject($project_id){
		$login_db = $this->ldb;
		$project_id = $login_db->real_escape_string($project_id);
		$req = "UPDATE `projects` SET `verified` = IF(`verified`=1, 0, 1) WHERE `project_id`='$project_id'";
		$login_db->query($req);
	}
	
	public function adminVerifyUser($user_id){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$req = "UPDATE `users` SET `verified` = IF(`verified`=1, 0, 1) WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}

	public function createProject($owner_id, $project_name){
		$login_db = $this->ldb;
		$owner_id = $login_db->real_escape_string($owner_id);
		$project_name = $login_db->real_escape_string($project_name);
		$time = time();
		$public_key = hash('sha256', $owner_id . "_" . $project_name . "_" . bin2hex(random_bytes(32)) . "_" . time());
		$private_key = hash('sha512', $owner_id . "_" . $project_name . "_" . bin2hex(random_bytes(32)) . bin2hex(random_bytes(32)) . "_" . time());
		$req = "INSERT INTO `projects`(`project_name`, `redirect_uri`, `secret_key`, `public_key`, `owner_id`, `verified`) VALUES ('$project_name', '', '$private_key', '$public_key', $owner_id, 0)";
		$login_db->query($req);
		return $login_db->insert_id;
	}

	public function regenerateProjectPublic($project_id, $owner_id, $project_name){
		$login_db = $this->ldb;
		$project_id = $login_db->real_escape_string($project_id);
		$owner_id = $login_db->real_escape_string($owner_id);
		$project_name = $login_db->real_escape_string($project_name);
		$public_key = hash('sha256', $owner_id . "_" . $project_name . "_" . bin2hex(random_bytes(32)) . "_" . time());
		$req = "UPDATE `projects` SET `public_key`='$public_key' WHERE `project_id`='$project_id'";
		$login_db->query($req);
	}

	public function regenerateProjectSecret($project_id, $owner_id, $project_name){
		$login_db = $this->ldb;
		$project_id = $login_db->real_escape_string($project_id);
		$owner_id = $login_db->real_escape_string($owner_id);
		$project_name = $login_db->real_escape_string($project_name);
		$secret_key = hash('sha512', $owner_id . "_" . $project_name . "_" . bin2hex(random_bytes(32)) . bin2hex(random_bytes(32)) . "_" . time());
		$req = "UPDATE `projects` SET `secret_key`='$secret_key' WHERE `project_id`='$project_id'";
		$login_db->query($req);
	}

	public function changeRedirectURL($project_id, $redirect_url){
		$login_db = $this->ldb;
		$project_id = $login_db->real_escape_string($project_id);
		$redirect_url = $login_db->real_escape_string($redirect_url);
		$req = "UPDATE `projects` SET `redirect_uri`='$redirect_url' WHERE `project_id`='$project_id'";
		$login_db->query($req);
	}

	public function changeProjectName($project_id, $name){
		$login_db = $this->ldb;
		$project_id = $login_db->real_escape_string($project_id);
		$name = $login_db->real_escape_string($name);
		$req = "UPDATE `projects` SET `project_name`='$name' WHERE `project_id`='$project_id'";
		$login_db->query($req);
	}

	public function getLoginProjectInfo($public_key){
		$login_db = $this->ldb;
		$public_key = $login_db->real_escape_string($public_key);
		$req = "SELECT `project_id`, `project_name`, `redirect_uri`, `secret_key`, `verified` FROM `projects` WHERE `public_key`='$public_key' AND `enabled`=1 AND `banned`=0";
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($project_id, $project_name, $redirect_uri, $secret_key, $verified);
		$project["exists"] = false;
		if($statement->fetch()){
			$project = array(
				"project_id" => $project_id,
				"project_name" => $project_name,
				"redirect_uri" => $redirect_uri,
				"secret_key" => $secret_key,
				"verified" => $verified,
				"exists" => true
			);
		}
		return $project;
	}

	public function setLastSID($user_id, $sid){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$sid = $login_db->real_escape_string($sid);
		$req = "UPDATE `users` SET `last_sid`='$sid' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}

	public function clearLastSID($user_id){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$req = "UPDATE `users` SET `last_sid`=null WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}

	public function countSessionsByIP($user_ip){
		$login_db = $this->ldb;
		$user_ip = $login_db->real_escape_string($user_ip);
		$req = "SELECT COUNT(*) FROM `sessions` WHERE `session_ip`='$user_ip'";
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($count);
		$statement->fetch();
		return $count;
	}

	public function deleteSessionsByIP($user_ip){
		$login_db = $this->ldb;
		$req = "DELETE FROM `sessions` WHERE `session_ip`='$user_ip'";
		$login_db->query($req);
	}

	public function setIPCode($user_id, $code){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$code = $login_db->real_escape_string($code);
		$req = "UPDATE `users` SET `ip_ver_code`='$code' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}

	public function clearIPCode($user_id){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$req = "UPDATE `users` SET `ip_ver_code`=NULL WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}

	public function setUserSalt($user_id, $salt){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$salt = $login_db->real_escape_string($salt);
		$req = "UPDATE `users` SET `user_salt`='$salt' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}
	
	public function getRequests($method, $user_ip){
		$login_db = $this->ldb;
		
		$method = $login_db->real_escape_string($method);
		$user_ip = $login_db->real_escape_string($user_ip);
		
		$req = "SELECT COUNT(*), `request_time` FROM `requests` WHERE `request_ip`='$user_ip' AND `method`='$method' GROUP BY `request_time` LIMIT 1";
		
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($count, $request_time);
		$statement->fetch();
		return ['count' => $count, 'time' => $request_time];
	}
	
	public function addRequest($method, $user_ip){
		$login_db = $this->ldb;
		
		$method = $login_db->real_escape_string($method);
		$user_ip = $login_db->real_escape_string($user_ip);
		$timestamp = time();
		
		$req = "INSERT INTO `requests`(`method`, `request_ip`, `request_time`) VALUES ('$method','$user_ip','$timestamp')";
		$login_db->query($req);
	}
	
	public function clearRequest($method, $user_ip){
		$login_db = $this->ldb;
		
		$method = $login_db->real_escape_string($method);
		$user_ip = $login_db->real_escape_string($user_ip);
		
		$req = "DELETE FROM `requests` WHERE `request_ip`='$user_ip' AND `method`='$method'";
		$login_db->query($req);
	}
	
	public function setEMailCheckState($user_id, $state){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$state = $login_db->real_escape_string($state);
		$req = "UPDATE `users` SET `email_check`='$state' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}
	
	public function banUser($user_id, $reason){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);
		$reason = $login_db->real_escape_string($reason);

		$req = "UPDATE `users` SET `is_banned`='1', `ban_reason`='$reason' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}
	
	public function unbanUser($user_id){
		$login_db = $this->ldb;
		$user_id = $login_db->real_escape_string($user_id);

		$req = "UPDATE `users` SET `is_banned`='0', `ban_reason`='' WHERE `user_id`='$user_id'";
		$login_db->query($req);
	}
	
	public function banProject($project_id){
		$login_db = $this->ldb;
		$project_id = $login_db->real_escape_string($project_id);

		$req = "UPDATE `projects` SET `banned`='1' WHERE `project_id`='$project_id'";
		$login_db->query($req);
	}
	
	public function unbanProject($project_id){
		$login_db = $this->ldb;
		$project_id = $login_db->real_escape_string($project_id);

		$req = "UPDATE `projects` SET `banned`='0' WHERE `project_id`='$project_id'";
		$login_db->query($req);
	}
	
	public function getRequestStats(){
		$login_db = $this->ldb;
		$req = "SELECT COUNT(*) FROM `requests`";
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($count);
		$statement->fetch();
		return $count;
	}
	
	public function getUserStats(){
		$login_db = $this->ldb;
		
		$req = "SELECT COUNT(*) FROM `users`";
		
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($count);
		$statement->fetch();
		return $count;
	}
	
	public function getProjectStats(){
		$login_db = $this->ldb;
		
		$req = "SELECT COUNT(*) FROM `projects`";
		
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($count);
		$statement->fetch();
		return $count;
	}
	
	public function cleanupRequests(){
		$login_db = $this->ldb;
		$req = "TRUNCATE `requests`";
		$login_db->query($req);
	}

	/* Webauthn Methods */
	public function getPKByCredentials($credential_id){
		$login_db = $this->ldb;
		
		$credential_id = $login_db->real_escape_string($credential_id);
		
		$req = "SELECT `user_id`, `owner_id`, `final_key` FROM `webauthn` WHERE `credential_id`='$credential_id'";
		
		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($user_id, $owner_id, $final_key);
		$response = false;
		if($statement->fetch()){
			$response = [
				"final_key" => $final_key,
				"owner_id" => $owner_id,
				"user_id" => $user_id
			];
		}
		return $response;
	}

	public function savePasskey($owner_id, $user_id, $final_key, $credential_id, $attest_format = "none"){
		$login_db = $this->ldb;
		
		$owner_id = $login_db->real_escape_string($owner_id);
		$user_id = $login_db->real_escape_string($user_id);
		$final_key = $login_db->real_escape_string($final_key);
		$credential_id = $login_db->real_escape_string($credential_id);
		$attest_format = $login_db->real_escape_string($attest_format);
		
		$req = "INSERT INTO `webauthn`(`user_id`, `owner_id`, `final_key`, `credential_id`, `attest_type`) VALUES ('$user_id','$owner_id','$final_key','$credential_id', '$attest_format')";
		$login_db->query($req);
	}

	public function getPasskeys($owner_id){
		$login_db = $this->ldb;
		
		$owner_id = $login_db->real_escape_string($owner_id);
		
		$req = "SELECT `keyID`, `attest_type` FROM `webauthn` WHERE `owner_id`='$owner_id'";

		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($keyID, $attest_type);
		$response = [];
		while($statement->fetch()){
			$response[] = array(
				'key_id' => $keyID,
				'attest_type' => $attest_type
			);
		}

		return $response;
	}

	public function getCredentialIDS($owner_id){
		$login_db = $this->ldb;
		
		$owner_id = $login_db->real_escape_string($owner_id);
		
		$req = "SELECT `credential_id` FROM `webauthn` WHERE `owner_id`='$owner_id'";

		$statement = $login_db->prepare($req);
		$statement->execute();
		$statement->bind_result($credential_id);
		$response = [];
		while($statement->fetch()){
			$response[] = base64_decode($credential_id);
		}

		return $response;
	}

	public function removePasskey($owner_id, $key_id){
		$login_db = $this->ldb;
		
		$owner_id = $login_db->real_escape_string($owner_id);
		$key_id = $login_db->real_escape_string($key_id);
		
		$req = "DELETE FROM `webauthn` WHERE `owner_id`='$owner_id' AND `keyID`='$key_id'";
		$login_db->query($req);
	}
}

?>