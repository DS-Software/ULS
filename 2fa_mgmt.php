<?php
	require 'config.php';
?>

<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<title>Двухфакторная Аутентификация</title>

<script>
	var token_xhr = new XMLHttpRequest();
	var xhr = new XMLHttpRequest();
	token_xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
	token_xhr.send();
	token_xhr.onload = function (e) {
		let access_token = JSON.parse(token_xhr.responseText);
		if(access_token.description == "2faVerificationRequired"){
			location.href = "2fa_check.php";
		}
		else{
			if(access_token.token != "" && access_token.result != "FAULT"){
				window.token = access_token.token;
				bootstrap();
			}
			else{
				window.token = "";
				bootstrap();
			}
		}
	}
	
	function bootstrap(){
		if(window.token == ""){
			location.href = "<?php echo($login_site) ?>";
		}
		else{
			get2FAInfo();
		}
	}
	
	function get2FAInfo(){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=totp&method=get2FAInfo&access_token=' + window.token, true);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				let el = document.getElementById('2fa_status');
				
				if(result.totp_active == 1){
					el.innerHTML = "Статус 2FA: <font color=\"#3274d6\">ВКЛЮЧЁН</font>";
					window.totp_enabled = true;
					let el2 = document.getElementById('2fa_disable');
					el2.style.display = '';
				}
				else{
					el.innerHTML = "Статус 2FA: <font color=\"#FF3333\">ОТКЛЮЧЁН</font>";
					window.totp_enabled = false;
					let el2 = document.getElementById('2fa_enable');
					el2.style.display = '';
				}				
			}
		}
	}
	
	function back(){
		location.href = "home.php";
	}
	
	function enable_totp(){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=totp&method=prepare_enable&access_token=' + window.token, true);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				let qr_link = result.url;
				let secret = result.secret;
				
				let qr = document.getElementById('TOTP_QR');
				qr.src = qr_link;
				let otp_secret = document.getElementById('otp_secret');
				otp_secret.innerHTML = secret;
				
				let el2 = document.getElementById('enable_totp');
				el2.style.display = '';
			}
		}
	}
	
	function disable_totp(){
		let el = document.getElementById('disable_totp');
		el.style.display = (el.style.display == 'none') ? '' : 'none';
	}
	
	function sumbit_otp_enable(){
		let otp = document.getElementById('otp');
		
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=totp&method=enable&access_token=' + window.token + "&otp=" + otp.value, true);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					let el2 = document.getElementById('enable_totp');
					el2.innerHTML = "<font size=\"15\">Вы успешно включили 2FA!<br><b>Пожалуйста, сохраните или запишите ключ отключения 2FA:</b></font><h2>" + result.disableCode + "</h2><font size=\"15\">Этот ключ позволит вам отключить 2FA при утере устройства-генератора кодов.<br>Если у вас уже был код отключения 2FA, он недействителен. Используйте вместо него ЭТОТ код.</font><br><b>Аккаунт: <?php echo($_COOKIE['email']) ?></b><br><br><button onclick=\"hideEnableForm()\" class=\"button_feature_new_mrg\">Закрыть</button>";
				}
				else{
					if(result.result == "FAULT" && result.reason == "WRONG_TOTP"){
						alert("Введённый OTP код недействителен!");
					}
					else{
						alert("В процессе обработки события произошла непредвиденная ошибка!");
						location.reload();
					}
				}
			}
		}
	}
	
	function hideEnableForm(){
		location.reload();
	}
	
	function sumbit_otp_disable(){
		let otp = document.getElementById('otp_dis');
		
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=totp&method=disable&access_token=' + window.token + "&otp=" + otp.value, true);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				if(result.result == "OK"){
					alert("Вы успешно отключили 2FA!");
					location.reload();
				}
				else{
					if(result.result == "FAULT" && result.reason == "WRONG_TOTP"){
						alert("Введённый OTP код недействителен!");
					}
					else{
						alert("В процессе обработки события произошла непредвиденная ошибка!");
						location.reload();
					}
				}
			}
		}
	}
</script>

<div class="main_module">
	<h1>Управление 2FA</h1>
	
	<h2 id="2fa_status">Статус 2FA: </h2>
	
	<div id="2fa_enable" style="display: none;">
		<button onclick="enable_totp()" class="button_feature_new_mrg">Включить 2FA</button>
		<div style="display: none;" id="enable_totp" class="text_container">
			<b>Отсканируйте этот QR Код, либо введите секретный ключ:</b><br>
			<span id="otp_secret"></span><br><img src="" id="TOTP_QR">
			<br>
			<div style="margin-left: 2%;">
				<b>Введите OTP для подтверждения:</b><br><br>
				<input name="otp" id="otp">
				
				<button onclick="sumbit_otp_enable()" class="button-7-new">Подтвердить</button>
			</div>
			<br>
		</div>
	</div>
	
	<div id="2fa_disable" style="display: none;">
		<button onclick="disable_totp()" class="button_feature_new_mrg">Отключить 2FA</button>
		<div style="display: none;" id="disable_totp" class="text_container">
			<div style="margin-left: 2%;">
				<b>Введите OTP для подтверждения:</b><br><br>
				<input name="otp_dis" id="otp_dis">
				
				<button onclick="sumbit_otp_disable()" class="button-7-new">Подтвердить</button>
			</div>
			<br>
		</div>
	</div>

	<button onclick="back()" class="button_return">Вернуться</button>
	<br>
</div>