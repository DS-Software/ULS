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

<title>Отключение 2FA</title>

<div class="login">
	<h1>Введите код отключения 2FA</h1>
	<form id="totp_form" action="javascript:void('')">
		<label for="password">
			<i class="fas fa-lock"></i>
		</label>
		<input type="text" name="dis_key" placeholder="Код отключения 2FA" id="dis_key" required>
		<br>
		<button class="button_login_new_totp" id="send" style="display: none;" onclick="disable(dis_key.value)">Отключить</button>
		<button class="button_cancel_new_mrg" onclick="back()">Вернуться</button>
	</form>
</div>

<script>

var input = document.getElementById('dis_key');

input.oninput = function() {
	if(input.value != ""){
		document.getElementById('send').style.display = '';
	}
	else{
		document.getElementById('send').style.display = 'none';
	}
};

function disable(key){
	var xhr = new XMLHttpRequest();
	xhr.withCredentials = true;
	xhr.open('GET', 'api.php?section=UNAUTH&method=disable_totp&key=' + key, true);
	xhr.send();
	xhr.onload = function (e) {
		let json = JSON.parse(xhr.responseText);
		if(json.result == "OK"){
			alertify.notify("Вы успешно отключили Двухфакторную Аутентификацию!", 'success', 2, function(){location.href="<?php echo(htmlspecialchars($login_site)); ?>"});
		}
		else{
			if(json.reason == "WRONG_DISABLE_KEY"){
				alertify.notify("Введённый код отключения Двухфакторной Аутентификации недействителен!", 'error', 5);
				return;
			}
			alertify.notify("Произошла ошибка при попытке отключения 2FA.", 'error', 5);
		}
	}
}

function back(){
	location.href = "<?php echo(htmlspecialchars(($login_site))); ?>";
}

</script>