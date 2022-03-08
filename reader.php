<?php
	require 'config.php';
?>

<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">

<link href="libs/alertify.min.css" rel="stylesheet">
<script src="libs/alertify.min.js"></script>

<title>EasyLogin</title>

<script src="libs/qr_reader.min.js"></script>

<div class="main_module" style="margin-top: 3%;">
	<h1>Вход в <?php echo(htmlspecialchars($email_info['$project_name'])) ?></h1>
	<div id="QR_Container" style="width: 90%; margin: auto; text-align: center;"><div style="width: 300px;" id="reader"></div></div>
	<br>
	<button onclick="back()" class="button_return">Вернуться</button>
	<br>
</div>

<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'api.php?section=UNAUTH&method=getAccessToken', true);
xhr.send();
xhr.onload = function (e) {
	let access_token = JSON.parse(xhr.responseText);
	switch (access_token.description) {
		case "2faVerificationRequired":
			location.href = "2fa_check.php";
			break;
		case "unfinishedReg":
			location.href = "finish_register.php";
			break;
		default:
			if(access_token.token != "" && access_token.result != "FAULT"){
				window.token = access_token.token;
			}
			else{
				back();
			}
			break;
	}
}

function back(){
	location.href = "home.php";
}

const html5QrCode = new Html5Qrcode("reader");
const qrCodeSuccessCallback = (decodedText, decodedResult) => {
    console.log(`Code matched = ${decodedText}`, decodedResult);
	html5QrCode.stop();
	let container = document.getElementById("reader");
	container.style.width = "300px";
	container.style.height = "300px";
	
	let begin_with_url = "<?php echo(htmlspecialchars($login_site)) ?>";
	if(decodedText.startsWith(begin_with_url)){
		location.href = decodedText;
	}
};
const config = { fps: 10, qrbox: { width: 250, height: 250 } };

// If you want to prefer back camera
html5QrCode.start({ facingMode: "environment" }, config, qrCodeSuccessCallback).catch(err => {
	alertify.confirm("Ошибка", "Произошла ошибка при работе с камерой!",
		function(){back()}, function(){back()});
});
</script>