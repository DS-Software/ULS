<?php
	require 'config.php';
?>
<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<title>Авторизация</title>

<div class="main_module">
	<h1>Выполнение Запроса</h1>
	<h2>Это может занять некоторое время...</h2>
	<br>
</div>

<script>
	var token_xhr = new XMLHttpRequest();
	token_xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
	token_xhr.send();
	token_xhr.onload = function (e) {
		let access_token = JSON.parse(token_xhr.responseText);
		if(access_token.token != "" && access_token.result != "FAULT"){
			location.href = "<?php echo($login_site) ?>";
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
		$link = "aa";
	}
	else{
		$link = "api.php?section=UNAUTH&method=restorePassword&rand_session_id=$rand_session_id&session_id=$session_id&timestamp=$timestamp&login=$login&email_ver_id=$email_ver_id";
	}
	
}

if($link != ""){
	?>
<script>
	function execute_task(){
		var command_xhr = new XMLHttpRequest();
		command_xhr.open('GET', "<?php echo($link) ?>", true);
		command_xhr.send();
		command_xhr.onload = function (e) {
			let response = JSON.parse(command_xhr.responseText);
			if(response.result != "OK"){
				alert("В процессе выполнения запроса произошла ошибка!");
			}
			location.href = "<?php echo($login_site) ?>";
		}
	}
</script>
	<?php
}
else{
	?>
<script>
	function execute_task(){
		location.href = "<?php echo($login_site) ?>";
	}
</script>
	<?php
}
?>