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

<title>Авторизация</title>

<div class="login-form" id="login_form">
	<h1 class="thin-text">Выполнение Запроса</h1>
	<div class="sep-line"></div>
	<h2 class="thin-text">Это может занять некоторое время...</h2>
	<br>
</div>

<script>
	var token_xhr = new XMLHttpRequest();
	token_xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
	token_xhr.send();
	token_xhr.onload = function (e) {
		let access_token = JSON.parse(token_xhr.responseText);
		if((access_token.token != "" && access_token.result != "FAULT") && "<?php echo(htmlspecialchars($_GET['method'])) ?>" != "changeEMail"){
			location.href = "home.php";
		}
		else{
			execute_task();
		}
	}
</script>

<?php

$method = $_GET['method'];

if($method == "emailIPValidation"){
	$rand_session_id = htmlspecialchars($_GET['rand_session_id']);
	$session_id = htmlspecialchars($_GET['session_id']);
	$timestamp = htmlspecialchars($_GET['timestamp']);
	$login = htmlspecialchars($_GET['login']);
	$password_hash = htmlspecialchars($_GET['password_hash']);
	$email_ver_id = htmlspecialchars($_GET['email_ver_id']);
	
	$link = "api.php?section=UNAUTH&method=emailIPValidation&rand_session_id=$rand_session_id&session_id=$session_id&timestamp=$timestamp&login=$login&password_hash=$password_hash&email_ver_id=$email_ver_id";
}
if($method == "registerNewUser"){
	$timestamp = htmlspecialchars($_GET['timestamp']);
	$login = htmlspecialchars($_GET['login']);
	$email_ver_id = htmlspecialchars($_GET['email_ver_id']);
	$session_id = htmlspecialchars($_GET['session_id']);
	$rand_session_id = htmlspecialchars($_GET['rand_session_id']);
	
	$link = "api.php?section=UNAUTH&method=registerNewUser&rand_session_id=$rand_session_id&session_id=$session_id&timestamp=$timestamp&login=$login&email_ver_id=$email_ver_id";
}

if($method == "restorePassword"){
	$timestamp = htmlspecialchars($_GET['timestamp']);
	$login = htmlspecialchars($_GET['login']);
	$email_ver_id = htmlspecialchars($_GET['email_ver_id']);
	$session_id = htmlspecialchars($_GET['session_id']);
	$rand_session_id = htmlspecialchars($_GET['rand_session_id']);
	$new_password = htmlspecialchars($_COOKIE['restore_password']);
	
	if($new_password == ""){
		$redirect = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";
		?>
<script>
	location.href = "new_password.php?redirect=<?php echo(urlencode($redirect)); ?>";
</script>
		<?php
		$link = "";
	}
	else{
		$link = "api.php?section=UNAUTH&method=restorePassword&rand_session_id=$rand_session_id&session_id=$session_id&timestamp=$timestamp&login=$login&email_ver_id=$email_ver_id";
	}
	
}

if($method == "changeEMail"){
	$timestamp = htmlspecialchars($_GET['timestamp']);
	$user_id = htmlspecialchars($_GET['user_id']);
	$email_ver_id = htmlspecialchars($_GET['email_ver_id']);
	$rand_session_id = htmlspecialchars($_GET['rand_session_id']);
	$session_id = htmlspecialchars($_GET['session_id']);
	$new_email = htmlspecialchars($_GET['new_email']);

	$link = "api.php?section=UNAUTH&method=changeUserEMail&rand_session_id=$rand_session_id&session_id=$session_id&timestamp=$timestamp&login=$login&email_ver_id=$email_ver_id&user_id=$user_id&new_mail=$new_email";
}

if($link != ""){
	?>
<script>
	
	function escapeHtml(text) {
	  var map = {
		'&amp;': '&'
	  };
	  
	  return text.replace(/[&<>"']/g, function(m) { return map[m]; });
	}

	function execute_task(){
		var command_xhr = new XMLHttpRequest();
		let link = "<?php echo(htmlspecialchars($link)) ?>";
		command_xhr.open('GET', link.replace(/&amp;/g, "&"), true);
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
</script>
	<?php
}
else{
	?>
<script>
	function execute_task(){
		location.href = "index.php";
	}
</script>
	<?php
}
?>