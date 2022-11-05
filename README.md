# DS Software ULS

This is a PHP implementation of a login system for DS Software.

## Usage

DS Software ULS is a standalone login system, so you don't have to install anything else.
### Configuration
The only file you need to modify is config.php.
* Configuration Steps:
  * Copy .configuration/example_config.php to your project root folder and rename it to config.php
    * Without it your project will NOT work!
  * Edit $login_site
    * Login site stands for a URL of index page of ULS.
  * Change Secured Values
    * $service_key is a secure key that allows ULS to verify data from external sources.
    * $encryption_key is a secure key that is used to encrypt user password in registration.
  * Insert Database Login Info
    * $database is used to connect to a MySQL database.
  * Insert Email Login Info
    * $email_settings are used to send service emails to users.

#### Configuration flags:
* $maintenance_mode
  * If `true`, API returns only error MAINTENANCE_MODE to all the requests.
    * Used, if you want to stop users from using ULS while maintaining it.
* $domain_name
  * Used to create cookies with proper path.
  * If you don't use root folder of your site, put the extension here:
    * If you use something like `https://dssoftware.ru/login` - put `/login` here
    * If you use something like `https://dssoftware.ru/` - leave `/`
    * If you use something like `https://example.dssoftware.ru/login` - put `/login` here
* $session_length
  * Defines the length of a random_session_id. If too small, RSID will duplicate. If too big, might cause some performance issues.
    * Optimal value - `32`
    
### Database Configuration
There is a Database Dump inside a .configuration folder. Use database_setup.sql as an Import File in PHPMyAdmin or just execute the SQL commands inside the file.

## License
This project is licensed under CC0 License.

## Credits
There is a list of all libraries that are used in ULS.
* ApMailer (https://github.com/anton-pribora/ApMailer)
* Browser Libs (https://www.php.net/manual/en/function.get-browser.php#101125)
* PHPQRCode (https://phpqrcode.sourceforge.net/index.php)
* PHP TOTP (https://github.com/lfkeitel/php-totp/)
* Html5-QRCode (https://github.com/mebjas/html5-qrcode)
* Alertify JS (https://github.com/MohammadYounes/AlertifyJS)
* KCaptcha (http://www.captcha.ru/kcaptcha/)

## Contributing & Issues
When contributing changes to the project, please provide as much detail on the changes. Malicious or meaningless contributions won't be accepted.
Please, if you found an issue in ULS, create a GitHub issue.
Besides, you can contact DS Software team: https://dssoftware.ru/about/
