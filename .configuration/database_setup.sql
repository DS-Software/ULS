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
  `enabled` int(11) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `requests` (
  `request_id` int(10) UNSIGNED NOT NULL,
  `method` text NOT NULL,
  `request_ip` text NOT NULL,
  `request_time` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `sessions` (
  `session_id` int(10) UNSIGNED NOT NULL,
  `session` text NOT NULL,
  `session_seed` text NOT NULL,
  `session_ip` text NOT NULL,
  `user_id` int(11) NOT NULL DEFAULT 0,
  `claimed` int(11) NOT NULL DEFAULT 0,
  `created` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

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
  `user_ip` text NOT NULL DEFAULT '',
  `api_key_seed` text DEFAULT NULL,
  `SLID` text NOT NULL DEFAULT '',
  `last_sid` text DEFAULT NULL,
  `easylogin` int(11) NOT NULL DEFAULT 0,
  `email_check` int(11) NOT NULL DEFAULT 1,
  `2fa_active` int(11) NOT NULL DEFAULT 0,
  `2fa_secret` text DEFAULT NULL,
  `2fa_disable_code` text DEFAULT NULL,
  `is_banned` int(11) NOT NULL DEFAULT 0,
  `ban_reason` text NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

ALTER TABLE `projects`
  ADD PRIMARY KEY (`project_id`);

ALTER TABLE `requests`
  ADD PRIMARY KEY (`request_id`);

ALTER TABLE `sessions`
  ADD PRIMARY KEY (`session_id`);

ALTER TABLE `users`
  ADD PRIMARY KEY (`user_id`);

ALTER TABLE `projects`
  MODIFY `project_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

ALTER TABLE `requests`
  MODIFY `request_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

ALTER TABLE `sessions`
  MODIFY `session_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

ALTER TABLE `users`
  MODIFY `user_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;
COMMIT;