<?php
	require 'config.php';
?>

<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<title>Проверка 2FA</title>

<div class="login">
	<h1>Введите OTP</h1>
	<form action="api.php" id="totp_form">
		<label for="password">
			<i class="fas fa-lock"></i>
		</label>
		<input type="number" name="otp" placeholder="Одноразовый Код 2FA" id="otp" required>
		<input name="method" value="check_totp" hidden>
		<input name="section" value="UNAUTH" hidden>
		<br>
		<button class="button_login_new_totp" id="send" style="display: none;">Отправить</button>
		<button class="button_cancel_new_mrg" type="button" onclick="totp_logout()">Выйти</button><br>
		<button class="button_cancel_new_mrg" type="button" onclick="disable_totp()">Отключить 2FA</button>
	</form>
</div>

<script>

var input = document.getElementById('otp');

input.oninput = function() {
	if(input.value != ""){
		document.getElementById('send').style.display = '';
	}
	else{
		document.getElementById('send').style.display = 'none';
	}
};

function totp_logout(){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken&totp_logout=true', true);
	xhr.send();
	xhr.onload = function (e) {
		location.href = "<?php echo($login_site); ?>";
	}
}

function disable_totp(){
	location.href = "2fa_disable.php";
}

</script>