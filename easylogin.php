<?php
	require 'config.php';
?>

<script>
	var xhr = new XMLHttpRequest();
	xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
	xhr.send();
	xhr.onload = function (e) {
		let access_token = JSON.parse(xhr.responseText);
		if(access_token.description == "2faVerificationRequired"){
			location.href = "2fa_check.php";
		}
		else{
			if(access_token.token != "" && access_token.result != "FAULT"){
				location.href = "home.php";
			}
		}
	}
</script>

<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<title>Беспарольный Вход</title>

<div class="main_module">
	<h1>Вход в DS Software ULS</h1>
	<div style="width: 80%; margin: auto;"><h2>Считайте QR код на устройстве, где вход в DS Software ULS уже был произведён:</h2></div>
	<div id="QR_Container" style="width: 90%; margin: auto; text-align: center;"><img id="session_container"></div>
	<button onclick="back()" class="button_feature_new_mrg">Вернуться</button>
	<br>
</div>

<script>
	var xhr2 = new XMLHttpRequest();

	function getELSession(){
		xhr2.open('GET', 'api.php?section=UNAUTH&method=el_getSession', true);
		xhr2.send();
		xhr2.onload = function (e) {
			let session = JSON.parse(xhr2.responseText);
			if(session.result == "OK"){
				window.el_session = session.session;
				window.session_verifier = session.session_verifier;
				
				var el = document.getElementById("session_container");
				el.src = session.session_qr;
				
				window.timeout = setTimeout(removeSession, 300000);
				window.interval = setInterval(checkSession, 400);
			}
			else{
				alert("Ошибка при получении сессии EasyLogin. Войдите обычным путём.");
				location.href = "<?php echo($login_site) ?>";
			}
		}
	}
	
	getELSession();
	
	function session_claimed(){
		let session_id = window.el_session;
	}
	
	function back(){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=UNAUTH&method=el_removeSession&session_id=' + window.el_session + "&session_ver=" + window.session_verifier, true);
		xhr.send();
		xhr.onload = function (e) {
			location.href = "<?php echo($login_site); ?>";
		}
	}
	
	function removeSession(){
		alert("Время сессии закончилось, повторите попытку!");
		back();
	}
	
	function checkSession(){
		var xhr = new XMLHttpRequest();
		xhr.open('GET', 'api.php?section=UNAUTH&method=el_checkSession&session_id=' + window.el_session + "&session_ver=" + window.session_verifier, true);
		xhr.send();
		xhr.onload = function (e) {
			let handler = JSON.parse(xhr.responseText);
			let handled = false;
			if(handler.result == "OK"){
				location.href = "<?php echo($login_site) ?>";
				clearInterval(window.interval);
				handled = true;
			}
			if(handler.result == "FAULT" && handler.reason == "UNCLAIMED"){
				console.log("[DEBUG] Discovered, that this session was unclaimed!");
				handled = true;
			}
			if(handler.result == "FAULT" && handler.reason == "THIS_FEATURE_WAS_DISABLED_BY_OWNER"){
				clearInterval(window.interval);
				alert("Чтобы использовать DS Software EasyLogin вам необходимо включить его в ЛК!");
				handled = true;
			}
			if(handler.result == "FAULT" && handler.reason == "WRONG_SESSION"){
				clearInterval(window.interval);
				handled = true;
			}
			
			if(!handled){
				clearInterval(window.interval);
				console.log("[FATAL] Unhandled exception. Closing session and returning!");
				alert("Произошла ошибка при обновлении статуса сессии!");
				back();
			}
		}
	}
</script>