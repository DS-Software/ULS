<?php
	require 'config.php';
?>

<link rel="stylesheet" href="style.css">
<link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v6.1.1/css/all.css">
<link href="libs/alertify.min.css" rel="stylesheet">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<script src="libs/main.js"></script>
<script src="libs/captcha_utils.php"></script>
<script src="libs/alertify.min.js"></script>
<script src="libs/qr_reader.min.js" async defer></script>
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Восстановление Пароля</title>

<div class="login-form" id="login_form">
	<h1 class="thin-text">Введите Новый Пароль</h1>
	<div class="sep-line"></div>
	<br>
	<div class="full-width">
		<div class="align-left icon">
			<i class="fa-solid fa-key"></i>
		</div>
		<span class="input-placeholder">Новый Пароль</span>
		<input class="text-input max-width input-field-decoration" type="text" id="new_password" autocomplete="on">
	</div>
	<br><br>
	<div class="align-left full-width">
		<button class="button-primary" onclick="restore(new_password.value)">Сменить</button>
		<button class="button-secondary float-right" onclick="genNewPwd()">Создать пароль</button>
	</div>
	<br><br>
</div>

<script>
prepare_view();

function genNewPwd(){
	let password = generatePass();
	new_password.value = password;
	new_password.type = "text";
	new_password.previousElementSibling.classList.add('placeholder-upper');
}
	
function generatePass(){
	let arr = window.crypto.getRandomValues(new BigUint64Array(1))[0].toString(36).split("");
	arr = arr.concat(window.crypto.getRandomValues(new BigUint64Array(1))[0].toString(36).split(""));
	arr = arr.slice(0, 16);
	arr.forEach(function(element, index){
		if(Math.round(Math.random())){
			arr[index] = element.toUpperCase();
		}
	});
		
	return arr.join("");
}

function restore(new_password){
	document.cookie = "restore_password=" + encodeURIComponent(new_password) + "; max-age=120";
	location.href = "<?php echo(strtr(htmlspecialchars($_GET['redirect']), ['&amp;' => '&'])) ?>";
}
</script>