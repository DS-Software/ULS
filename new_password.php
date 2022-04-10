<?php
	require 'config.php';
?>

<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<title>Восстановление Пароля</title>

<div class="login">
	<h1>Введите Новый Пароль</h1>
	<form action="javascript:void('')" id="restore_form">
		<label for="password">
			<i class="fas fa-lock"></i>
		</label>
		<input type="password" name="new_password" placeholder="Новый Пароль" id="new_password" required>
		<br>
		<button class="button_login_new_long" onclick="restore(new_password.value)">Сохранить</button>
	</form>
	<br>
</div>

<script>
	function restore(new_password){
		document.cookie = "restore_password=" + encodeURIComponent(new_password) + "; max-age=120";
		location.href = "<?php echo(strtr(htmlspecialchars($_GET['redirect']), ['&amp;' => '&'])) ?>";
	}
</script>