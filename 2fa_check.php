<?php
	require 'config.php';
?>

<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">

<link href="libs/alertify.min.css" rel="stylesheet">
<script src="libs/alertify.min.js"></script>

<title>Проверка 2FA</title>

<div class="login">
	<h1>Введите OTP</h1>
	<form action="javascript:void('')" id="totp_form">
		<label for="password">
			<i class="fas fa-lock"></i>
		</label>
		<input type="number" name="otp" placeholder="Одноразовый Код 2FA" id="otp" required>
		<br>
		<button class="button_login_new_totp" id="send" style="display: none;" onclick="check_totp_code(otp.value)">Отправить</button>
		<button class="button_cancel_new_mrg" type="button" onclick="totp_logout()">Выйти</button><br>
		<button class="button_cancel_new_mrg" type="button" onclick="disableTOTP()">Отключить 2FA</button>
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
		location.href = "<?php echo(htmlspecialchars($login_site)); ?>";
	}
}

function disableTOTP(){
	location.href = "2fa_disable.php";
}

function check_totp_code(otp){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=UNAUTH&method=checkTOTP&otp=' + otp, true);
	xhr.send();
	xhr.onload = function (e) {
		let json = JSON.parse(xhr.responseText);
		if(json.result == "FAULT"){
			if(json.reason == "WRONG_2FA_CODE"){
				alertify.notify("Вы ввели неверный код двухфакторной аутентификации!", 'error', 5);
			}
			else{
				alertify.notify("Произошла непредвиденная ошибка!", 'error', 5);
			}
		}
		else{
			alertify.notify("Вы успешно прошли проверку!", 'success', 2, function(){location.href="<?php echo(htmlspecialchars($login_site)); ?>"});
		}
	}
}

</script>