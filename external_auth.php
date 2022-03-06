<?php
	require 'config.php';
	
	$scopes= getScopes($_GET['scopes']);
?>


<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<title>Авторизация</title>

<link href="libs/alertify.min.css" rel="stylesheet">
<script src="libs/alertify.min.js"></script>

<div class="main_module">
	<h1>Авторизация</h1>
	<form id="el_form" action="javascript:void('')">
		<h2 class="center" style="width: 90%; margin-bottom: 0; padding-bottom: 0;" id="project_name"></h2>
		<h2 class="center" style="width: 90%; margin-top: 0; padding-top: 0;">запрашивает доступ к вашему аккаунту.</h2>
		
		<div class="center" style="width: 70%; text-align: left;">
			<?php if($scopes['email']){ ?>
			<b>Доступ к общей информации</b><br>
			•&nbsp;Приложение узнает Вашу основную почту.
			<br><br>
			<?php }
			
			if($scopes['personal']){ ?>
			<b>Доступ к личной информации</b><br>
			•&nbsp;Приложение получит доступ к Вашей личной информации.
			<br><br>
			<?php } 
			
			if($scopes['auth']){ ?>
			<b>Проверка Данных</b><br>
			•&nbsp;Приложение узнает ваш ключ авторизации.
			<br><br>
			<?php }
			
			if($scopes['profile_management']){ ?>
			<b>Управление Аккаунтом</b><br>
			•&nbsp;Приложение сможет управлять вашим аккаунтом!
			<br><br>
			<?php } ?>
		</div>
		
		<button class="button_submit" onclick="authenticate()">Продолжить</button>
		<button class="button_cancel_new" onclick="back()">Вернуться</button>
		<br>
	</form>
</div>

<script>

	window.fault_redirect  = "index.php";

	function back(){
		location.href = window.fault_redirect;
	}

	var token_xhr = new XMLHttpRequest();
	token_xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
	token_xhr.send();
	token_xhr.onload = function (e) {
		let access_token = JSON.parse(token_xhr.responseText);
		switch (access_token.description) {
			case "2faVerificationRequired":
				location.href = "2fa_check.php";
				break;
			case "unfinishedReg":
				location.href = "finish_register.php";
				break;
			default:
				window.token = access_token.token;
				bootstrap();
				break;
		}
	}
	
	function bootstrap(){
		if(window.token == "" || window.token == undefined){
			back();
		}
		else{
			getProjectInfo();
		}
	}
	
	function getProjectInfo(){
		let project_public = "<?php echo(htmlspecialchars($_GET['public'])); ?>";
		let scopes = "<?php echo(htmlspecialchars($_GET['scopes'])); ?>";
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=projects&method=getProjectInfo&public=' + project_public + "&onFault=<?php echo(htmlspecialchars($_GET['onFault'])); ?>&sign=<?php echo(htmlspecialchars($_GET['sign'])); ?>", true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			let result = JSON.parse(xhr.responseText);
			
			if(result.result != "FAULT"){
				let project_name = result.project_name;
				let verified = result.verified;
				
				if(result.fault_redirect != "MALFORMED"){
					window.fault_redirect = result.fault_redirect;
				}
				
				let name_container = document.getElementById("project_name");
				name_container.textContent = project_name;
				if(verified == 1){
					let verification_mark = "<span class=\"verify_mark\">Verified</span>";
					name_container.innerHTML = name_container.innerHTML + " " + verification_mark;
				}
			}
			else{
				alertify.notify("Произошла ошибка при авторизации! Повторите вход в необходимом сервисе!", 'error', 2, function(){back()});
			}
		}
	}
	
	function authenticate(){
		<?php if($scopes['profile_management']){ ?>
		alertify.confirm("Внимание!", "При продолжении, это приложение сможет управлять вашим аккаунтом! Не давайте это разрешение приложениям, которым вы не доверяете!",
			function(){ sendrequest()},
			function(){
				console.log("[DEBUG] Cancelled Potentially Malicious Consent.")
			}
		);
		<?php } 
		else { ?>
		sendrequest();
		<?php } ?>
	}
	
	function sendrequest(){
		let project_public = "<?php echo(htmlspecialchars($_GET['public'])); ?>";
		let scopes = "<?php echo(htmlspecialchars($_GET['scopes'])); ?>";
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=projects&method=login&public=' + project_public + '&scopes=' + scopes, true);
		xhr.setRequestHeader("Authorization", "Bearer " + window.token);
		xhr.send();
		xhr.onload = function (e) {
			let result = JSON.parse(xhr.responseText);
			
			if(result.redirect != "" && result.redirect != undefined){
				location.href = result.redirect;
			}
			else{
				alertify.notify("Произошла ошибка при авторизации! Повторите вход в необходимом сервисе!", 'error', 2, function(){back()});
			}
		}
	}
</script>