<?php

$messageNewIPSubject = "Вход в DS Software ULS со стороннего IP Адреса";
$messageRegisterSubject = "Регистрация в DS Software ULS";
$messageRestoreSubject = "Восстановление Пароля в DS Software ULS";
$messageChangeEMailSubject = "Подтверждение Изменения Основной Почты";

$registerEmail = <<<EOT
<div class="email" style="background-color: #F5F5F5;color: #000000;font-family: 'Noto Sans', sans-serif;">
	<div class="header" align="center">
		<br>
		<h1>{$messageRegisterSubject}</h1>
	</div>
	<div class="email_body" style="background-color: #ffffff; width: 50%; border-radius: 50px;margin-left: auto;margin-right: auto;text-align: center;border: 2px solid #D5D5D5;">
		<h3>
			<br>
			На ваш адрес <span>\$messageTo</span> была запрошена ссылка для регистрации на сайте <span>{$login_site}</span>.<br><br>Если это были вы, то пройдите по ссылке ниже, иначе - проигнорируйте это письмо.<br><br>Ссылка для продолжения регистрации:<br><span><a href=\$link>{$login_site}</a></span><br>Эта ссылка будет действительна в течении 15 минут после её запроса.<br><br>
		</h3>
	</div>
	<br>
	<br>
</div>
EOT;

$NewIPEmail = <<<EOT
<div class="email" style="background-color: #F5F5F5;color: #000000;font-family: 'Noto Sans', sans-serif;">
	<div class="header" align="center">
		<br>
		<h1>{$messageNewIPSubject}</h1>
	</div>
	<div class="email_body" style="background-color: #ffffff; width: 50%; border-radius: 50px;margin-left: auto;margin-right: auto;text-align: center;border: 2px solid #D5D5D5;">
		<h3>
			<br>
			Вы зашли на <a href='$login_site'>{$login_site}</a> с нового IP адреса <span>\$ip</span>.<br><br>Если это были вы, то пройдите по ссылке ниже, иначе - смените ваш пароль.<br><br>Ссылка для входа:<br><a href=\$link>{$login_site}</a><br>Эта ссылка будет действительна в течении 15 минут после её запроса.<br><br>
		</h3>
	</div>
	<br>
	<br>
</div>
EOT;

$restorePasswordEmail = <<<EOT
<div class="email" style="background-color: #F5F5F5;color: #000000;font-family: 'Noto Sans', sans-serif;">
	<div class="header" align="center">
		<br>
		<h1>{$messageRestoreSubject}</h1>
	</div>
	<div class="email_body" style="background-color: #ffffff; width: 50%; border-radius: 50px;margin-left: auto;margin-right: auto;text-align: center;border: 2px solid #D5D5D5;">
		<h3>
			<br>
			Вы запросили восстановление пароля на <a href='$login_site'>{$login_site}</a>.<br><br>Если это были вы, то пройдите по ссылке ниже, иначе - проигнорируйте это письмо.<br><br>Ссылка для изменения пароля:<br><span><a href=\$link>{$login_site}</a></span><br>Эта ссылка будет действительна в течении 15 минут после её запроса.<br><br>
		</h3>
	</div>
	<br>
	<br>
</div>
EOT;

$changeEMail = <<<EOT
<div class="email" style="background-color: #F5F5F5;color: #000000;font-family: 'Noto Sans', sans-serif;">
	<div class="header" align="center">
		<br>
		<h1>{$messageChangeEMailSubject}</h1>
	</div>
	<div class="email_body" style="background-color: #ffffff; width: 50%; border-radius: 50px;margin-left: auto;margin-right: auto;text-align: center;border: 2px solid #D5D5D5;">
		<h3>
			<br>
			Вы запросили изменение почты на сайте <a href='$login_site'>{$login_site}</a> на почту \$new_mail.<br><br>Если это были вы, то пройдите по ссылке ниже, иначе - проигнорируйте это письмо.<br><br>Ссылка для смены почты:<br><span><a href=\$link>{$login_site}</a></span><br>Эта ссылка будет действительна в течении 5 минут после её запроса.<br><br>
		</h3>
	</div>
	<br>
	<br>
</div>
EOT;

?>