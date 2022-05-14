<?php

$messageNewIPSubject = "Вход в \$project_name со стороннего IP Адреса";
$messageRegisterSubject = "Регистрация в \$project_name";
$messageRestoreSubject = "Восстановление Пароля в \$project_name";
$messageChangeEMailSubject = "Подтверждение Изменения Основной Почты";

$registerEmail = <<<EOT
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
 <head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" /
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
</head>
<body style="margin: 0; padding: 0; background-color: #f5f5f5;">
	<br>
	<br>
    <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse;">
        <tr>
                <td align="center"><a href="\$main_link" style="font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; text-decoration: none; color: #4f545c; font-weight: 700; font-size: 30px;">DS Software ULS</a></td>
           </tr>
           <tr>
            <td style="text-align:center; background-color: #ffffff; vertical-align:top;direction:ltr;font-size:0px;padding:40px 50px">
             <h3 style="font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-weight: 500; font-size: 20px; color: #4f545c; letter-spacing: 0.27px;">Здравствуйте!</h3>
             <p style="color: #737f8d; font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-size: 16px; line-height: 24px; text-align: left;">Добро пожаловать в систему авторизации \$project_name! Это единный удобный и безопасный вход на все сайты. Для завершения регистрации, подтвердите свою электронную почту.</p>
             <img src="\$main_link/img/hello.jpg" width="520" height="400" >
             <span style="margin-top: 30px; border-style: solid solid solid solid;     border-color: #191215 #191215 #191215 #191215;     background: #191215;     border-width: 4px 4px 4px 4px;     display: inline-block;     border-radius: 5px;     width: auto;">
                <a href="\$link" style="border-style: solid;     border-color: #191214;     border-width: 10px 20px 10px 20px;     display: inline-block;     background: #191214;     border-radius: 30px;     font-size: 18px;     font-family: arial, 'helvetica neue', helvetica, sans-serif;     font-weight: normal;     font-style: normal;     line-height: 120%;     color: #ffffff;     text-decoration: none !important;     width: auto;     text-align: center;">Подтвердить</a>
             </span>
            </td>
           </tr>
           <tr>
               <td style="text-align:center;vertical-align:top;direction:ltr;font-size:0px; background-color: #ffffffff;">
                <hr>
                <p style="color: #747f8d; font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-size: 13px; line-height: 16px; text-align: center;">Проблемы с регистрацией? Свяжитесь с нами: <a a style="text-decoration: underline; color: #111" href='\$support_email'>\$support_email_label</a></p>
               </td>
           </tr>
          </table>
		  <br>
		  <br>
   </body>
</html>
EOT;

$NewIPEmail = <<<EOT
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
 <head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
</head>
<body style="margin: 0; padding: 0; background-color: #f5f5f5;">
	<br>
	<br>
    <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse;">
        <tr>
                <td align="center"><a href="\$main_link" style="font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; text-decoration: none; color: #4f545c; font-weight: 700; font-size: 30px;">DS Software ULS</a></td>
           </tr>
		   <br>
           <tr>
            <td style="text-align:center; background-color: #ffffff; vertical-align:top;direction:ltr;font-size:0px;padding:40px 50px">
             <h3 style="font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-weight: 500; font-size: 20px; color: #4f545c; letter-spacing: 0.27px;">Здравствуйте, \$username!</h3>
             <p style="color: #737f8d; font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-size: 16px; line-height: 24px; text-align: left;">С вашего аккаунта был произведен вход с нового IP-Адреса. Если это вы, введите код, указанный ниже, чтобы подтвердить вход. Если это не вы, смените пароль, как можно скорее!</p><br><br><br>
             <h4 style="color: #4f545c; font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-size: 18px; line-height: 24px; text-align: left;">Сайт:<a style="text-decoration: underline; color: #111" href='\$login_site'> \$login_site</a> <br>IP-Адрес: <a style="color: #111">\$ip</a></h4>
             <p style="color: #737f8d; font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-size: 16px; line-height: 24px; text-align: left;">P.S. Мы настоятельно рекомендуем вам настроить для своей учётной записи двухфакторную аутентификацию в панели управления аккаунтом.</p>
             <span style="margin-top: 28px; border-style: solid solid solid solid;     border-color: #191215 #191215 #191215 #191215;     background: #191215;     border-width: 4px 4px 4px 4px;     display: inline-block;     border-radius: 5px;     width: auto;">
                <span style="border-style: solid;     border-color: #191214;     border-width: 10px 20px 10px 20px;     display: inline-block;     background: #191213;     border-radius: 30px;     font-size: 25px;     font-family: arial, 'helvetica neue', helvetica, sans-serif;     font-weight: normal;     font-style: normal;     line-height: 120%;     color: #ffffff;     text-decoration: none !important;     width: auto;     text-align: center;">\$code</span>
             </span>
            </td>
           </tr>
           <tr>
               <td style="text-align:center;vertical-align:top;direction:ltr;font-size:0px; background-color: #ffffffff;">
                <hr>
                <p style="color: #747f8d; font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-size: 13px; line-height: 16px; text-align: center;">Проблемы со входом? Свяжитесь с нами: <a a style="text-decoration: underline; color: #111" href='\$support_email'>\$support_email_label</a></p>
               </td>
           </tr>
          </table>
		  <br>
		  <br>
   </body>
</html>
EOT;

$restorePasswordEmail = <<<EOT
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
 <head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
</head>
<body style="margin: 0; padding: 0; background-color: #f5f5f5;">
	<br>
	<br>
    <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse;">
        <tr>
                <td align="center"><a href="\$main_link" style="font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; text-decoration: none; color: #4f545c; font-weight: 700; font-size: 30px;">DS Software ULS</a></td>
           </tr>
		   <br>
           <tr>
            <td style="text-align:center; background-color: #ffffff; vertical-align:top;direction:ltr;font-size:0px;padding:40px 50px">
             <h3 style="font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-weight: 500; font-size: 20px; color: #4f545c; letter-spacing: 0.27px;">Здравствуйте, \$username!</h3>
             <p style="color: #737f8d; font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-size: 16px; line-height: 24px; text-align: left;">С вашего аккаунта поступила заявка на смену пароля. Если это вы, перейдите по ссылке ниже, чтобы сменить пароль. Если это не вы, проигнорируйте данное письмо. Вы в безопасности.</p><br><br><br>
             <h4 style="color: #4f545c; font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-size: 18px; line-height: 24px; text-align: left;">Сайт:<a style="text-decoration: underline; color: #111" href='\$login_site'> \$login_site</a> <br>IP-Адрес: <a style="color: #111">\$ip</a></h4>
             <p style="color: #737f8d; font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-size: 16px; line-height: 24px; text-align: left;">P.S. Мы настоятельно рекомендуем вам настроить для своей учётной записи двухфакторную аутентификацию в панели управления аккаунтом.</p>
             <span style="margin-top: 28px; border-style: solid solid solid solid;     border-color: #191215 #191215 #191215 #191215;     background: #191215;     border-width: 4px 4px 4px 4px;     display: inline-block;     border-radius: 5px;     width: auto;">
                <a href="\$link" style="border-style: solid;     border-color: #191214;     border-width: 10px 20px 10px 20px;     display: inline-block;     background: #191214;     border-radius: 30px;     font-size: 18px;     font-family: arial, 'helvetica neue', helvetica, sans-serif;     font-weight: normal;     font-style: normal;     line-height: 120%;     color: #ffffff;     text-decoration: none !important;     width: auto;     text-align: center;">Сменить пароль </a>
             </span>
            </td>
           </tr>
           <tr>
               <td style="text-align:center;vertical-align:top;direction:ltr;font-size:0px; background-color: #ffffffff;">
                <hr>
                <p style="color: #747f8d; font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-size: 13px; line-height: 16px; text-align: center;">Проблемы со сменой пароля? Свяжитесь с нами: <a a style="text-decoration: underline; color: #111" href='\$support_email'>\$support_email_label</a></p>
               </td>
           </tr>
          </table>
		  <br>
		  <br>
   </body>
</html>
EOT;

$changeEMail = <<<EOT
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
 <head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
</head>
<body style="margin: 0; padding: 0; background-color: #f5f5f5;">
	<br>
	<br>
    <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse;">
        <tr>
                <td align="center"><a href="\$main_link" style="font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; text-decoration: none; color: #4f545c; font-weight: 700; font-size: 30px;">DS Software ULS</a></td>
           </tr>
		   <br>
           <tr>
            <td style="text-align:center; background-color: #ffffff; vertical-align:top;direction:ltr;font-size:0px;padding:40px 50px">
             <h3 style="font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-weight: 500; font-size: 20px; color: #4f545c; letter-spacing: 0.27px;">Здравствуйте, \$username!</h3>
             <p style="color: #737f8d; font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-size: 16px; line-height: 24px; text-align: left;">С вашего аккаунта поступила заявка на смену электронной почты. Если это вы, перейдите по ссылке ниже, чтобы сменить почту. Если это не вы, проигнорируйте данное письмо. Вы в безопасности.</p><br><br><br>
             <h4 style="color: #4f545c; font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-size: 18px; line-height: 24px; text-align: left;">Сайт:<a style="text-decoration: underline; color: #111" href='\$login_site'> \$login_site</a> <br>IP-Адрес: <a style="color: #111">\$ip</a><br>Новый EMail: <a style="color: #111">\$new_email</a></h4>
             <p style="color: #737f8d; font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-size: 16px; line-height: 24px; text-align: left;">P.S. Мы настоятельно рекомендуем вам настроить для своей учётной записи двухфакторную аутентификацию в панели управления аккаунтом.</p>
             <span style="margin-top: 28px; border-style: solid solid solid solid;     border-color: #191215 #191215 #191215 #191215;     background: #191215;     border-width: 4px 4px 4px 4px;     display: inline-block;     border-radius: 5px;     width: auto;">
                <a href="\$link" style="border-style: solid;     border-color: #191214;     border-width: 10px 20px 10px 20px;     display: inline-block;     background: #191214;     border-radius: 30px;     font-size: 18px;     font-family: arial, 'helvetica neue', helvetica, sans-serif;     font-weight: normal;     font-style: normal;     line-height: 120%;     color: #ffffff;     text-decoration: none !important;     width: auto;     text-align: center;">Сменить почту </a>
             </span>
            </td>
           </tr>
           <tr>
               <td style="text-align:center;vertical-align:top;direction:ltr;font-size:0px; background-color: #ffffffff;">
                <hr>
                <p style="color: #747f8d; font-family: Whitney,Helvetica Neue,Helvetica,Arial,Lucida Grande,sans-serif; font-size: 13px; line-height: 16px; text-align: center;">Проблемы со сменой почты? Свяжитесь с нами: <a a style="text-decoration: underline; color: #111" href='\$support_email'>\$support_email_label</a></p>
               </td>
           </tr>
          </table>
		  <br>
		  <br>
   </body>
</html>
EOT;

?>