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

<title>Подтверждение нового IP</title>

<div class="login">
	<h1>Введите Код Подтверждения</h1>
	<span style="width: 90%; text-align: center; margin: auto; display: block;"><b>Подтверждение нового IP необходимо, чтобы защитить ваш аккаунт от несанкционированного доступа, если доступ к вашему паролю получит злоумышленник.</b></span>
	<form action="javascript:void('')" id="ip_form">
		<label for="ver_code">
			<i class="fas fa-lock"></i>
		</label>
		<input type="text" name="ver_code" placeholder="Код Подтверждения" id="ver_code" required>
		<br>
		<button class="button_login_new_totp" id="send" style="display: none;" onclick="check_ip_code(ver_code.value)">Отправить</button>
		<button class="button_cancel_new_mrg" type="button" onclick="logout()">Выйти</button><br>
	</form>
</div>

<script>

var input = document.getElementById('ver_code');

input.oninput = function() {
	if(input.value != ""){
		document.getElementById('send').style.display = '';
	}
	else{
		document.getElementById('send').style.display = 'none';
	}
};

function logout(){
	document.cookie = 'user_id=; Max-Age=0;';
	document.cookie = 'email=; Max-Age=0;';
	document.cookie = 'user_ip=; Max-Age=0;';
	document.cookie = 'user_verkey=; Max-Age=0;';
	document.cookie = 'session=; Max-Age=0;';
	document.cookie = 'SLID=; Max-Age=0;';
	document.cookie = 'ip_verify=; Max-Age=0;';
	location.href = "index.php";
}

function check_ip_code(ver_code){
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=UNAUTH&method=verifyIP&code=' + ver_code, true);
	xhr.send();
	xhr.onload = function (e) {
		let json = JSON.parse(xhr.responseText);
		if(json.result == "FAULT"){
			if(json.reason == "WRONG_VER_CODE"){
				alertify.notify("Вы ввели неверный Код Подтверждения!", 'error', 5);
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