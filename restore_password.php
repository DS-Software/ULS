<?php
	require 'config.php';
?>

<script>
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
	xhr.send();
	xhr.onload = function (e) {
		let access_token = JSON.parse(xhr.responseText);
		if(access_token.description == "2faVerificationRequired"){
			location.href = "2fa_check.php";
		}
		else{
			if(access_token.token != "" && access_token.result != "FAULT"){
				location.href = "home.php";
			}
		}
	}
</script>

<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<title>Восстановление Пароля</title>

<div class="login" style="text-align: center;">
	<h1>Восстановление Пароля</h1>
	<form action="javascript:void('interception auto-post')" id="restore_form">
		<label for="username">
			<i class="fas fa-user"></i>
		</label>
		<input type="text" name="username" placeholder="Почта" id="username" required>
		<br>
		<button onclick="restore(username.value)" class="button_login_new_long">Восстановить</button>
		<button onclick="back()" class="button_additional_long">Вернуться</button>
	</form>
</div>

<script>

	var f = document.querySelector('#restore_form');
	f.addEventListener('submit', e => {
		e.preventDefault();
	});
	
	var xhr2 = new XMLHttpRequest();

	function restore(login){
		if(login == ''){
			return;
		}
		xhr.open('GET', 'api.php?section=UNAUTH&method=send_restore_email&login=' + login, true);
		xhr.send();
		xhr.onload = function (e) {
			let reg_result = JSON.parse(xhr.responseText);
			if(reg_result.description == "emailVerificationNeeded"){
				alert("Вам было отправлено письмо для восстановления пароля!");
				location.href = "<?php echo($login_site) ?>";
			}
			if(reg_result.reason == "NO_ACCOUNT"){
				alert("Этот E-Mail не привязан ни к одному аккаунту!");
			}
			if(reg_result.reason == "INVALID_EMAIL"){
				alert("Введённый E-Mail недействителен!");
			}
		}
	}
	
	function back(){
		location.href = "<?php echo($login_site); ?>";
	}
</script>