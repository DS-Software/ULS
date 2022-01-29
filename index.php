<link href="style.css" rel="stylesheet" type="text/css">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans&display=swap" rel="stylesheet">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.1/css/all.css">
<link rel="shortcut icon" href="favicon.gif" type="image/gif">
<title>Главная</title>

<?php
require 'config.php';

if(isset($_REQUEST['redirect'])){
	$redirect = $_REQUEST['redirect'];
	
	if($projects[$redirect]['url'] != ''){
		setcookie("redirect", $redirect, time() + 2629743, $domain_name);
	}
}

if($maintenance_mode){
	?>
	<div class="main_module">
		<h1>Сервис недоступен!</h1>
		<h2>В текущий момент сервис DS Software<br>ULS недоступен. Подробнее:<br><a href="https://status.ds-software.xyz">Status Page</a></h2>
		<h2>Извините за причинённые неудобства!</h2>
		<br>
	</div>
	<?php
	die();
}
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

<div class="login">
	<h1>Вход в DS Software ULS</h1>
	<form action="javascript:void('interception auto-post')" id="login_form">
		<label for="username">
			<i class="fas fa-user"></i>
		</label>
		<input type="text" name="username" placeholder="Логин" id="username" required>
		<br>
		<label for="password">
			<i class="fas fa-lock"></i>
		</label>
		<input type="password" name="password" placeholder="Пароль" id="password" required>
		<button onclick="login(username.value, password.value)" class="button_login_new">Войти</button>
		<button onclick="register()" class="button_additional_new">Регистрация</button>
		
		<button onclick="restore()" class="button_additional_long_nomrg">Восстановить Пароль</button>
		<button onclick="easylogin()" class="button_login_new_long_mrg">Беспарольный Вход</button>
	</form>
</div>

<script>

	var f = document.querySelector('#login_form');
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

	function login(login, password){
		if(login == '' || password == ''){
			return;
		}
		xhr.open('GET', 'api.php?section=UNAUTH&method=getAuthChallenge', true);
		xhr.send();
		xhr.onload = function (e) {
			let auth_challenge = JSON.parse(xhr.responseText);
			let password_token = sha256(sha256(password) + '_' + auth_challenge.session_id + '_' + auth_challenge.user_ip + '_' + auth_challenge.timestamp + '_' + auth_challenge.rand_session_id + '_' + login);
			xhr2.open('GET', 'api.php?section=UNAUTH&method=verifyAuthChallenge&rand_session_id=' + auth_challenge.rand_session_id + '&session_id=' + auth_challenge.session_id + '&timestamp=' + auth_challenge.timestamp + '&login=' + login + '&password_hash=' + password_token, true);
			xhr2.send();
			xhr2.onload = function (e) {
				let auth_result = JSON.parse(xhr2.responseText);		
				if(auth_result.result == 'FAULT'){
					if(auth_result.reason == 'WRONG_SESSION'){
						alert('Неверная сессия, обновите страницу!');
					}
					if(auth_result.reason == 'THIS_SESSION_IS_EXPIRED'){
						alert('Устаревшая сессия, обновите страницу!');
					}
					if(auth_result.reason == 'WRONG_LOGIN'){
						alert('Неверный логин!');
					}
					if(auth_result.reason == 'WRONG_PASSWORD'){
						alert('Неверный пароль!');
					}
				}
				else{
					if(auth_result.description == "Success"){
						location.href = "home.php";
					}
					if(auth_result.description == "emailVerificationNeeded"){
						alert("Вам было отправлено письмо для подтверждения нового IP адреса!");
						location.href = "home.php";
					}
				}
			}
		}
	}
	
	function register(){
		location.href = "register.php";
	}
	function restore(){
		location.href = "restore_password.php";
	}
	
	function easylogin(){
		location.href = "easylogin.php";
	}
	
	var error = "<?php echo($_GET['error']) ?>";
	if(error == "INVALID_LINK"){
		alert("Вы перешли по недействительной ссылке! Попробуйте ещё раз!");
		location.href = "<?php echo($login_site) ?>";
	}
	if(error == "PASSWORD_CORRUPTED"){
		alert("Ссылка была повреждена! Попробуйте ещё раз!");
		location.href = "<?php echo($login_site) ?>";
	}
	if(error == "EMAIL_WAS_TAKEN"){
		alert("Аккаунт уже был зарегистрирован на эту почту! Войдите, либо восстановите пароль!");
		location.href = "<?php echo($login_site) ?>";
	}
	if(error == "EXPIRED_LINK"){
		alert("Ссылка из письма устарела! Попробуйте ещё раз!");
		location.href = "<?php echo($login_site) ?>";
	}
	
	var state = "<?php echo($_GET['state']) ?>";
	if(state == "CHANGED_SUCCESSFULLY"){
		alert("Пароль был успешно изменён!");
		location.href = "<?php echo($login_site) ?>";
	}
</script>