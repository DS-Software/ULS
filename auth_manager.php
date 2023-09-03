<link rel="stylesheet" href="style.css">
<link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">
<link href="libs/alertify.min.css" rel="stylesheet">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<script src="libs/main.js"></script>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<script src="libs/captcha_utils.php"></script>
<script src="libs/alertify.min.js"></script>
<script src="libs/qr_reader.min.js" async defer></script>
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Авторизация</title>

<div class="login-form" id="login_form">
	<h1 class="thin-text">Выполнение Запроса</h1>
	<div class="sep-line"></div>
	<h2 class="thin-text">Это может занять некоторое время...</h2>
	<br>
</div>

<script>
	window.prevent_cmd = false;
	prepare_view();
	function getCookie(name) {
		var r = document.cookie.match("\\b" + name + "=([^;]*)\\b");
		return r ? r[1] : null;
	};

	window.params = (new URL(document.location)).searchParams;
	var token_xhr = new XMLHttpRequest();
	token_xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
	token_xhr.send();
	token_xhr.onload = function (e) {
		let access_token = JSON.parse(token_xhr.responseText);
		if((access_token.token != "" && access_token.result != "FAULT") && window.params.get('method') != "changeEMail"){
			location.href = "home.php";
		}
	}
	
	let method = window.params.get('method');
	let link = "";
	
	if(method == "registerNewUser"){
		let timestamp = encodeURIComponent(window.params.get('timestamp'));
		let login = encodeURIComponent(window.params.get('login'));
		let email_ver_id = encodeURIComponent(window.params.get('email_ver_id'));
		let session_id = encodeURIComponent(window.params.get('session_id'));
		let rand_session_id = encodeURIComponent(window.params.get('rand_session_id'));
		
		link = "api.php?section=UNAUTH&method=registerNewUser&rand_session_id=" + rand_session_id +"&session_id=" + session_id + "&timestamp=" + timestamp +"&login=" + login + "&email_ver_id=" + email_ver_id;
	}
	
	if(method == "restorePassword"){
		let timestamp = encodeURIComponent(window.params.get('timestamp'));
		let login = encodeURIComponent(window.params.get('login'));
		let email_ver_id = encodeURIComponent(window.params.get('email_ver_id'));
		let session_id = encodeURIComponent(window.params.get('session_id'));
		let rand_session_id = encodeURIComponent(window.params.get('rand_session_id'));
		let new_password = getCookie("restore_password");
		
		if(new_password == null){
			location.href = "new_password.php?redirect=" + encodeURIComponent(location.href);
			window.prevent_cmd = true;
			
		}
		else{
			link = "api.php?section=UNAUTH&method=restorePassword&rand_session_id=" + rand_session_id +"&session_id=" + session_id + "&timestamp=" + timestamp +"&login=" + login + "&email_ver_id=" + email_ver_id;
		}
	}
	
	if(method == "changeEMail"){
		let timestamp = encodeURIComponent(window.params.get('timestamp'));
		let user_id = encodeURIComponent(window.params.get('user_id'));
		let email_ver_id = encodeURIComponent(window.params.get('email_ver_id'));
		let session_id = encodeURIComponent(window.params.get('session_id'));
		let rand_session_id = encodeURIComponent(window.params.get('rand_session_id'));
		let new_email = encodeURIComponent(window.params.get('new_email'));
		
		link = "api.php?section=UNAUTH&method=changeUserEMail&rand_session_id=" + rand_session_id +"&session_id=" + session_id + "&timestamp=" + timestamp +"&user_id=" + user_id + "&email_ver_id=" + email_ver_id + "&new_mail=" + new_email;
	}
	
	function execute_task(){
		if(window.prevent_cmd){
			return;
		}
		if(link != ""){
			var command_xhr = new XMLHttpRequest();
			command_xhr.open('GET', link, true);
			command_xhr.send();
			command_xhr.onload = function (e) {
				let response = JSON.parse(command_xhr.responseText);
				if(response.result != "OK"){
					if(response.reason == 'RATE_LIMIT_EXCEEDED'){
						window.failed_request = function(){
							execute_task();
						};
						callCaptcha();
						return;
					}
					alertify.confirm("Ошибка", "Произошла ошибка в процессе выполнения запроса!<br>Код ошибки: " + response.reason,
						function(){location.href="index.php"}, function(){location.href="index.php"}
					);
				}
				else{
					location.href = "index.php";
				}
			}
		}
		else{
			location.href = "index.php";
		}
	}
	
	execute_task();
</script>