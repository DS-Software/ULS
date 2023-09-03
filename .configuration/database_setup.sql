SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

CREATE TABLE `projects` (
  `project_id` int(10) UNSIGNED NOT NULL,
  `project_name` text NOT NULL,
  `redirect_uri` text NOT NULL,
  `secret_key` text NOT NULL,
  `public_key` text NOT NULL,
  `owner_id` int(11) NOT NULL,
  `verified` int(11) NOT NULL,
  `enabled` int(11) NOT NULL DEFAULT 1,
  `banned` int(11) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `requests` (
  `request_id` int(10) UNSIGNED NOT NULL,
  `method` text NOT NULL,
  `request_ip` text NOT NULL,
  `request_time` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `users` (
  `user_id` int(10) UNSIGNED NOT NULL,
  `user_nick` text DEFAULT NULL,
  `user_email` text NOT NULL,
  `user_name` text DEFAULT NULL,
  `user_surname` text DEFAULT NULL,
  `verified` int(11) NOT NULL DEFAULT 0,
  `birthday` int(11) DEFAULT NULL,
  `user_salt` text DEFAULT NULL,
  `password_hash` text NOT NULL,
  `ip_ver_code` text DEFAULT NULL,
  `user_ip` text DEFAULT NULL,
  `api_key_seed` text DEFAULT NULL,
  `SLID` text DEFAULT NULL,
  `last_sid` text DEFAULT NULL,
  `email_check` int(11) NOT NULL DEFAULT 1,
  `2fa_active` int(11) NOT NULL DEFAULT 0,
  `2fa_secret` text DEFAULT NULL,
  `2fa_disable_code` text DEFAULT NULL,
  `is_banned` int(11) NOT NULL DEFAULT 0,
  `ban_reason` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

CREATE TABLE `webauthn` (
  `keyID` int(10) UNSIGNED NOT NULL,
  `user_id` text NOT NULL,
  `owner_id` int(11) NOT NULL,
  `final_key` mediumtext DEFAULT NULL,
  `credential_id` text DEFAULT NULL,
  `attest_type` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

ALTER TABLE `projects`
  ADD PRIMARY KEY (`project_id`);

ALTER TABLE `requests`
  ADD PRIMARY KEY (`request_id`);

ALTER TABLE `users`
  ADD PRIMARY KEY (`user_id`);

ALTER TABLE `webauthn`
  ADD PRIMARY KEY (`keyID`);

ALTER TABLE `projects`
  MODIFY `project_id` int(1) UNSIGNED NOT NULL AUTO_INCREMENT;

ALTER TABLE `requests`
  MODIFY `request_id` int(1) UNSIGNED NOT NULL AUTO_INCREMENT;

ALTER TABLE `users`
  MODIFY `user_id` int(1) UNSIGNED NOT NULL AUTO_INCREMENT;

ALTER TABLE `webauthn`
  MODIFY `keyID` int(1) UNSIGNED NOT NULL AUTO_INCREMENT;
COMMIT;