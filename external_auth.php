<?php
	require 'config.php';
?>


<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<title>Авторизация</title>

<div class="main_module">
	<h1>Перенаправление...</h1>
	<h2>Сейчас Вы будете<br>перенаправлены на сайт проекта.</h2>
	<br>
</div>

<script>
	var token_xhr = new XMLHttpRequest();
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
			location.href = "<?php echo(htmlspecialchars($login_site)) ?>";
		}
		else{
			authenticate();
		}
	}
	
	function authenticate(){
		let project_public = "<?php echo(htmlspecialchars($_GET['public'])); ?>";
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=projects&method=login&public=' + project_public, true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			let result = JSON.parse(xhr.responseText);
			
			if(result.redirect != "" && result.redirect != undefined){
				location.href = result.redirect;
			}
			else{
				alert("Произошла ошибка при авторизации! Повторите вход в необходимом сервисе!");
				location.href = "index.php";
			}
		}
	}
</script>