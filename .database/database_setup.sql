SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

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
  `user_email` text NOT NULL,
  `password_hash` text NOT NULL,
  `user_ip` text NOT NULL DEFAULT '',
  `api_key_seed` text DEFAULT NULL,
  `SLID` text NOT NULL DEFAULT '',
  `easylogin` int(11) NOT NULL DEFAULT 0,
  `2fa_active` int(11) NOT NULL DEFAULT 0,
  `2fa_secret` text DEFAULT NULL,
  `2fa_disable_code` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

ALTER TABLE `sessions`
  ADD PRIMARY KEY (`session_id`);

ALTER TABLE `users`
  ADD PRIMARY KEY (`user_id`);
  
ALTER TABLE `sessions`
  MODIFY `session_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=25;

ALTER TABLE `users`
  MODIFY `user_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;
COMMIT;
