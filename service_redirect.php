<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">

<div class="main_module">
	<h1>Перенаправление...</h1>
	<h2>Сейчас Вы будете<br>перенаправлены на сайт проекта.</h2>
	<br>
</div>

<?php
	require_once "config.php";
?>

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
			if("<?php echo($_COOKIE['redirect']) ?>" != ""){
				xhr.open('GET', 'api.php?section=projects&method=login&project=' + "<?php echo($_COOKIE['redirect']) ?>" + '&access_token=' + window.token, true);
				xhr.send();
				xhr.onload = function (e) {
					<?php
						setcookie("redirect", '', 0, "/");
					?>
					let redirect_info = JSON.parse(xhr.responseText);
					if(redirect_info.result == "OK"){
						location.href = redirect_info.url;
					}
					if(redirect_info.result == "FAULT"){
						location.href = "<?php echo($login_site) ?>";
					}
				}
			}
			else{
				location.href = "<?php echo($login_site) ?>";
			}
		}
	}
</script>