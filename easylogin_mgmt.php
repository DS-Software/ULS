<?php
	require 'config.php';
?>

<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<title>DS Software EasyLogin</title>

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
			getEasyLoginInfo();
		}
	}
	
	function getEasyLoginInfo(){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=easylogin&method=getEasyLoginInfo', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				let el = document.getElementById('el_status');
				
				if(result.easylogin_active == 1){
					el.innerHTML = "Статус EasyLogin: <font color=\"#3274d6\">ВКЛЮЧЁН</font>";
					window.easylogin_active = true;
					let el2 = document.getElementById('el_disable');
					el2.style.display = '';
				}
				else{
					el.innerHTML = "Статус EasyLogin: <font color=\"#FF3333\">ОТКЛЮЧЁН</font>";
					window.easylogin_active = false;
					let el2 = document.getElementById('el_enable');
					el2.style.display = '';
				}				
			}
		}
	}
	
	function back(){
		location.href = "home.php";
	}
	
	function enable_el(){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=easylogin&method=enable', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				
				if(result.result == "FAULT"){
					alert("Произошла ошибка при включении EasyLogin!");
				}
				location.reload();
			}
		}
	}
	
	function disable_el(){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=easylogin&method=disable', true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			if (xhr.readyState == 4 && xhr.status == 200) {
				let result = JSON.parse(xhr.responseText);
				
				if(result.result == "FAULT"){
					alert("Произошла ошибка при отключении EasyLogin!");
				}
				location.reload();
			}
		}
	}
</script>

<div class="main_module">
	<h1>Управление EasyLogin</h1>
	
	<h2 id="el_status">Статус EasyLogin: </h2>
	
	<div id="el_enable" style="display: none;">
		<button onclick="enable_el()" class="button_feature_new_mrg">Включить EasyLogin</button>
	</div>
	
	<div id="el_disable" style="display: none;">
		<button onclick="disable_el()" class="button_feature_new_mrg">Отключить EasyLogin</button>
	</div>

	<button onclick="back()" class="button_return">Вернуться</button>
	<br>
</div>