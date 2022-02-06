<?php

class database{
		
		private $ldb;
		
		public function __construct($database){
			$botdb = new mysqli($database['hostname'], $database['login'], $database['password'], $database['dbname']);
			$this->ldb = $botdb;
			$this->ldb->set_charset("utf8mb4");
			$this->db_info = $database;
		}
		
		public function get_user_info($user_id){
			$login_db = $this->ldb;
			$user_id = $login_db->real_escape_string($user_id);
			$req = "SELECT `user_id`, `user_email`, `password_hash`, `user_ip`, `api_key_seed`, `SLID`, `2fa_active`, `2fa_secret`, `2fa_disable_code`, `easylogin` FROM `users` WHERE `user_id`='$user_id'";
			$statement = $login_db->prepare($req);
			$statement->execute();
			$statement->bind_result($user_id, $user_email, $password_hash, $user_ip, $api_key_seed, $SLID, $totp_active, $totp_secret, $totp_disable_code, $easylogin);
			while($statement->fetch()) {
				$user_object = array(
					'user_id' => $user_id,
					'user_email' => $user_email,
					'password_hash' => $password_hash,
					'user_ip' => $user_ip,
					'api_key_seed' => $api_key_seed,
					'SLID' => $SLID,
					'2fa_active' => $totp_active,
					'2fa_secret' => $totp_secret,
					'2fa_disable_code' => $totp_disable_code,
					'easylogin' => $easylogin
				);
			}
			
			return $user_object;
		}
		
		public function getUIDByEMail($email){
			$login_db = $this->ldb;
			$email = $login_db->real_escape_string($email);
			$req = "SELECT `user_id` FROM `users` WHERE `user_email`='{$email}'";
			$statement = $login_db->prepare($req);
			$statement->execute();
			$statement->bind_result($user_id);
			$statement->fetch();
			return $user_id;
		}
		
		public function set_current_user_ip($user_id, $ip){
			$login_db = $this->ldb;
			$user_id = $login_db->real_escape_string($user_id);
			$ip = $login_db->real_escape_string($ip);
			$req = "UPDATE `users` SET `user_ip`='{$ip}' WHERE `user_id`='{$user_id}'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function disable_totp($user_id){
			$login_db = $this->ldb;
			$user_id = $login_db->real_escape_string($user_id);
			$req = "UPDATE `users` SET `2fa_active`=0 WHERE `user_id`='{$user_id}'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function enable_totp($user_id){
			$login_db = $this->ldb;
			$user_id = $login_db->real_escape_string($user_id);
			$req = "UPDATE `users` SET `2fa_active`=1 WHERE `user_id`='{$user_id}'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function disable_el($user_id){
			$login_db = $this->ldb;
			$user_id = $login_db->real_escape_string($user_id);
			$req = "UPDATE `users` SET `easylogin`=0 WHERE `user_id`='{$user_id}'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function enable_el($user_id){
			$login_db = $this->ldb;
			$user_id = $login_db->real_escape_string($user_id);
			$req = "UPDATE `users` SET `easylogin`=1 WHERE `user_id`='{$user_id}'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function set_totp_secret($user_id, $totp_secret){
			$login_db = $this->ldb;
			$user_id = $login_db->real_escape_string($user_id);
			$totp_secret = $login_db->real_escape_string($totp_secret);
			$req = "UPDATE `users` SET `2fa_active`=0, `2fa_secret`='{$totp_secret}' WHERE `user_id`='{$user_id}'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function set_TOTP_disable_code($user_id, $code){
			$login_db = $this->ldb;
			$user_id = $login_db->real_escape_string($user_id);
			$hash_code = hash('sha256', $code . "_" . $user_id);
			$req = "UPDATE `users` SET `2fa_disable_code`='{$hash_code}' WHERE `user_id`='$user_id'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function create_new_user($email, $password_hash){
			$login_db = $this->ldb;
			$email = $login_db->real_escape_string($email);
			$password_hash = $login_db->real_escape_string($password_hash);
			$req = "INSERT INTO `users`(`user_email`, `password_hash`) VALUES ('$email', '$password_hash')";
			$login_db->query($req, MYSQLI_STORE_RESULT);
			return $login_db->insert_id;
		}
		
		public function regenerateAPIKey($user_id){
			$login_db = $this->ldb;
			$user_id = $login_db->real_escape_string($user_id);
			$random_uuid = hash('sha256', $user_id . bin2hex(random_bytes(64)) . time());
			$req = "UPDATE `users` SET `api_key_seed`='{$random_uuid}' WHERE `user_id`='$user_id'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function regenerateSLID($user_id){
			$login_db = $this->ldb;
			$user_id = $login_db->real_escape_string($user_id);
			$random_uuid = hash('sha256', $user_id . bin2hex(random_bytes(32)) . time());
			$req = "UPDATE `users` SET `SLID`='{$random_uuid}' WHERE `user_id`='$user_id'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function changeUserPassword($user_id, $password_hash){
			$login_db = $this->ldb;
			$user_id = $login_db->real_escape_string($user_id);
			$password_hash = $login_db->real_escape_string($password_hash);
			$req = "UPDATE `users` SET `password_hash` = '$password_hash' WHERE `user_id`='$user_id'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function changeUserEmail($user_id, $user_email){
			$login_db = $this->ldb;
			$user_id = $login_db->real_escape_string($user_id);
			$user_email = $login_db->real_escape_string($user_email);
			$req = "UPDATE `users` SET `user_email` = '$user_email' WHERE `user_id`='$user_id'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function wasEmailRegistered($user_email){
			$login_db = $this->ldb;
			$user_email = $login_db->real_escape_string($user_email);
			$req = "SELECT `user_id` FROM `users` WHERE `user_email`='{$user_email}'";
			$statement = $login_db->prepare($req);
			$statement->execute();
			$statement->bind_result($user_id);
			$result = false;
			while($statement->fetch()) {
				$result = true;
			}
			return $result;
		}
		
		public function create_session($session_key, $session_salt, $ip){
			$login_db = $this->ldb;
			$session_key = $login_db->real_escape_string($session_key);
			$session_salt = $login_db->real_escape_string($session_salt);
			$ip = $login_db->real_escape_string($ip);
			$created = time();
			$req = "INSERT INTO `sessions`(`session`, `session_seed`, `claimed`, `created`, `session_ip`) VALUES ('$session_key', '$session_salt', 0, $created, '$ip')";
			$login_db->query($req, MYSQLI_STORE_RESULT);
			return $login_db->insert_id;
		}
		
		public function get_session($session_key){
			$login_db = $this->ldb;
			$session_key = $login_db->real_escape_string($session_key);
			$req = "SELECT `session`, `session_seed`, `user_id`, `claimed`, `created`, `session_ip` FROM `sessions` WHERE `session`='{$session_key}'";
			$statement = $login_db->prepare($req);
			$statement->execute();
			$statement->bind_result($session, $session_seed, $user_id, $claimed, $created, $ip);
			while($statement->fetch()) {
				$result = array(
					'session' => $session,
					'session_seed' => $session_seed,
					'user_id' => $user_id,
					'claimed' => $claimed,
					'created' => $created,
					'ip' => $ip
				);
			}
			return $result;
		}
		
		public function claim_session($user_id, $session_key){
			$login_db = $this->ldb;
			$user_id = $login_db->real_escape_string($user_id);
			$session_key = $login_db->real_escape_string($session_key);
			$req = "UPDATE `sessions` SET `claimed`=1, `user_id`='$user_id' WHERE `session`='{$session_key}' AND `claimed`=0";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function delete_session($session_key){
			$login_db = $this->ldb;
			$session_key = $login_db->real_escape_string($session_key);
			$req = "DELETE FROM `sessions` WHERE `session`='{$session_key}'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function cleanUpProjects($delete = false, $timeout = 8035200){
			if($delete){
				$login_db = $this->ldb;
				$time = time() - $timeout;
				$req = "DELETE FROM `projects` WHERE `last_used`<$time AND `infinite`=0";
				$login_db->query($req, MYSQLI_STORE_RESULT);
			}
		}
		
		public function getUserProjects($owner_id){
			$login_db = $this->ldb;
			$owner_id = $login_db->real_escape_string($owner_id);
			$req = "SELECT `project_id`, `project_name` FROM `projects` WHERE `owner_id`='{$owner_id}'";
			$statement = $login_db->prepare($req);
			$statement->execute();
			$statement->bind_result($project_id, $project_name);
			while($statement->fetch()) {
				$projects[$project_id] = array(
					"project_id" => $project_id,
					"project_name" => $project_name
				);
			}
			return $projects;
		}
		
		public function getProjectInfo($project_id){
			$login_db = $this->ldb;
			$project_id = $login_db->real_escape_string($project_id);
			$req = "SELECT `project_id`, `project_name`, `redirect_uri`, `secret_key`, `public_key`, `last_used`, `owner_id`, `infinite` FROM `projects` WHERE `project_id`='{$project_id}'";
			$statement = $login_db->prepare($req);
			$statement->execute();
			$statement->bind_result($project_id, $project_name, $redirect_uri, $secret_key, $public_key, $last_used, $owner_id, $infinite);
			while($statement->fetch()) {
				$project = array(
					"project_id" => $project_id,
					"project_name" => $project_name,
					"redirect_uri" => $redirect_uri,
					"secret_key" => $secret_key,
					"public_key" => $public_key,
					"last_used" => $last_used,
					"owner_id" => $owner_id,
					"infinite" => $infinite
				);
			}
			return $project;
		}
		
		public function createProject($owner_id, $project_name){
			$login_db = $this->ldb;
			$owner_id = $login_db->real_escape_string($owner_id);
			$project_name = $login_db->real_escape_string($project_name);
			$time = time();
			$public_key = hash('sha256', $owner_id . "_" . $project_name . "_" . bin2hex(random_bytes(32)) . "_" . time());
			$private_key = hash('sha512', $owner_id . "_" . $project_name . "_" . bin2hex(random_bytes(32)) . bin2hex(random_bytes(32)) . "_" . time());
			$req = "INSERT INTO `projects`(`project_name`, `redirect_uri`, `secret_key`, `public_key`, `owner_id`, `last_used`, `infinite`) VALUES ('$project_name', '', '$private_key', '$public_key', $owner_id, $time, 0)";
			$login_db->query($req, MYSQLI_STORE_RESULT);
			return $login_db->insert_id;
		}
		
		public function regenerateProjectPublic($project_id){
			$login_db = $this->ldb;
			$project_id = $login_db->real_escape_string($project_id);
			$public_key = hash('sha256', $owner_id . "_" . $project_name . "_" . bin2hex(random_bytes(32)) . "_" . time());
			$req = "UPDATE `projects` SET `public_key`='{$public_key}' WHERE `project_id`='$project_id'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function regenerateProjectSecret($project_id){
			$login_db = $this->ldb;
			$project_id = $login_db->real_escape_string($project_id);
			$secret_key = hash('sha512', $owner_id . "_" . $project_name . "_" . bin2hex(random_bytes(32)) . bin2hex(random_bytes(32)) . "_" . time());
			$req = "UPDATE `projects` SET `secret_key`='{$secret_key}' WHERE `project_id`='$project_id'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function changeRedirectURL($project_id, $redirect_url){
			$login_db = $this->ldb;
			$project_id = $login_db->real_escape_string($project_id);
			$redirect_url = $login_db->real_escape_string($redirect_url);
			$req = "UPDATE `projects` SET `redirect_uri`='{$redirect_url}' WHERE `project_id`='$project_id'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function changeProjectName($project_id, $name){
			$login_db = $this->ldb;
			$project_id = $login_db->real_escape_string($project_id);
			$name = $login_db->real_escape_string($name);
			$req = "UPDATE `projects` SET `project_name`='{$name}' WHERE `project_id`='$project_id'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
		
		public function getProjectInfoByPublic($public_key){
			$login_db = $this->ldb;
			$public_key = $login_db->real_escape_string($public_key);
			$req = "SELECT `project_id`, `project_name`, `redirect_uri`, `secret_key`, `public_key`, `last_used`, `owner_id`, `infinite` FROM `projects` WHERE `public_key`='{$public_key}'";
			$statement = $login_db->prepare($req);
			$statement->execute();
			$statement->bind_result($project_id, $project_name, $redirect_uri, $secret_key, $public_key, $last_used, $owner_id, $infinite);
			while($statement->fetch()) {
				$project = array(
					"project_id" => $project_id,
					"project_name" => $project_name,
					"redirect_uri" => $redirect_uri,
					"secret_key" => $secret_key,
					"public_key" => $public_key,
					"last_used" => $last_used,
					"owner_id" => $owner_id,
					"infinite" => $infinite
				);
			}
			return $project;
		}
		
		public function getProjectInfoBySecret($secret){
			$login_db = $this->ldb;
			$secret = $login_db->real_escape_string($secret);
			$req = "SELECT `project_id`, `project_name`, `redirect_uri`, `secret_key`, `public_key`, `last_used`, `owner_id`, `infinite` FROM `projects` WHERE `secret_key`='{$secret}'";
			$statement = $login_db->prepare($req);
			$statement->execute();
			$statement->bind_result($project_id, $project_name, $redirect_uri, $secret_key, $public_key, $last_used, $owner_id, $infinite);
			while($statement->fetch()) {
				$project = array(
					"project_id" => $project_id,
					"project_name" => $project_name,
					"redirect_uri" => $redirect_uri,
					"secret_key" => $secret_key,
					"public_key" => $public_key,
					"last_used" => $last_used,
					"owner_id" => $owner_id,
					"infinite" => $infinite
				);
			}
			return $project;
		}
		
		public function updateProjectLastUsed($project_id){
			$login_db = $this->ldb;
			$project_id = $login_db->real_escape_string($project_id);
			$last_used = time();
			$req = "UPDATE `projects` SET `last_used`='{$last_used}' WHERE `project_id`='$project_id'";
			$login_db->query($req, MYSQLI_STORE_RESULT);
		}
}

?>