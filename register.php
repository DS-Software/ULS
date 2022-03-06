<?php
	require 'config.php';
?>

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
					location.href = "home.php";
				}
				break;
		}
	}
</script>

<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">

<link href="libs/alertify.min.css" rel="stylesheet">
<script src="libs/alertify.min.js"></script>

<title>Регистрация</title>

<div class="login register">
	<h1>Регистрация</h1>
	<form action="javascript:void('interception auto-post')" id="register_form">
		<label for="username">
			<i class="fas fa-user"></i>
		</label>
		<input type="email" name="email" placeholder="Почта" id="email" required>
		<br>
		<label for="password">
			<i class="fas fa-lock"></i>
		</label>
		<input type="password" name="new_password" placeholder="Новый Пароль" id="new_password" autocomplete="new-password" required>
		<button onclick="register(email.value, new_password.value)" class="button_login_new_long">Зарегистрироваться</button>
		<button onclick="back()" class="button_additional_long">Вернуться</button>
	</form>
</div>

<script>

	var f = document.querySelector('#register_form');
	f.addEventListener('submit', e => {
		e.preventDefault();
	});
	
	function sha256(ascii) {
		function rightRotate(value, amount) {
			return (value>>>amount) | (value<<(32 - amount));
		};
		
		var mathPow = Math.pow;
		var maxWord = mathPow(2, 32);
		var lengthProperty = 'length'
		var i, j; 
		var result = ''
		var words = [];
		var asciiBitLength = ascii[lengthProperty]*8;
					
		var hash = sha256.h = sha256.h || [];
		var k = sha256.k = sha256.k || [];
		var primeCounter = k[lengthProperty];

		var isComposite = {};
		for (var candidate = 2; primeCounter < 64; candidate++) {
			if (!isComposite[candidate]) {
				for (i = 0; i < 313; i += candidate) {
					isComposite[i] = candidate;
				}
				hash[primeCounter] = (mathPow(candidate, .5)*maxWord)|0;
				k[primeCounter++] = (mathPow(candidate, 1/3)*maxWord)|0;
			}
		}
					
		ascii += '\x80'
		while (ascii[lengthProperty]%64 - 56) ascii += '\x00'
		for (i = 0; i < ascii[lengthProperty]; i++) {
			j = ascii.charCodeAt(i);
			if (j>>8) return; // ASCII check: only accept characters in range 0-255
			words[i>>2] |= j << ((3 - i)%4)*8;
		}
		words[words[lengthProperty]] = ((asciiBitLength/maxWord)|0);
		words[words[lengthProperty]] = (asciiBitLength)
		
		for (j = 0; j < words[lengthProperty];) {
			var w = words.slice(j, j += 16);
			var oldHash = hash;
			hash = hash.slice(0, 8);
						
			for (i = 0; i < 64; i++) {
				var i2 = i + j;
				var w15 = w[i - 15], w2 = w[i - 2];

				var a = hash[0], e = hash[4];
				var temp1 = hash[7]
					+ (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) // S1
					+ ((e&hash[5])^((~e)&hash[6])) // ch
					+ k[i] + (w[i] = (i < 16) ? w[i] : (
						w[i - 16]
						+ (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15>>>3)) // s0
						+ w[i - 7]
						+ (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2>>>10)) // s1
					)|0
				);
				var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) // S0
					+ ((a&hash[1])^(a&hash[2])^(hash[1]&hash[2])); // maj
				
				hash = [(temp1 + temp2)|0].concat(hash); 
					hash[4] = (hash[4] + temp1)|0;
			}
						
			for (i = 0; i < 8; i++) {
				hash[i] = (hash[i] + oldHash[i])|0;
			}
		}
					
		for (i = 0; i < 8; i++) {
			for (j = 3; j + 1; j--) {
				var b = (hash[i]>>(j*8))&255;
				result += ((b < 16) ? 0 : '') + b.toString(16);
			}
		}
		return result;
	};
	var xhr2 = new XMLHttpRequest();

	function register(login, password){
		if(login == '' || password == ''){
			return;
		}
		let password_hash = sha256(password);
		xhr.open('GET', 'api.php?section=UNAUTH&method=send_register_message&login=' + login + "&password_hash=" + password_hash, true);
		xhr.send();
		xhr.onload = function (e) {
			let reg_result = JSON.parse(xhr.responseText);
			if(reg_result.description == "emailVerificationNeeded"){
				alertify.notify("Вам было отправлено письмо для продолжения регистрации!", 'message', 2, function(){location.href = "<?php echo(htmlspecialchars($login_site)) ?>"});
			}
			if(reg_result.reason == "INVALID_EMAIL"){
				alertify.notify("Введённый E-Mail недействителен!", 'error', 5);
			}
		}
	}
	
	function back(){
		location.href = "<?php echo(htmlspecialchars($login_site)); ?>";
	}
</script>