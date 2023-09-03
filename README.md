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
	
* $spam_check
  * If `true`, users won't be able to use disposal emails.
* $spam_provide
  * Sets the provider to check emails whether they are disposable or not.
  
* $captcha_required
  * If `true`, API will count user requests and issue proper RATE_LIMIT_EXCEEDED errors.
* $turnstile_public
  * Required in order to work with CloudFlare Turnstile. Your Site Key.
* $turnstile_private
  * Required in order to work with CloudFlare Turnstile. Your Secret Key.
  
* $login_site
  * URL of main page.
* $status_page
  * URL of status page.
* $support
  * Support e-mail or link
	
* $domain_name
  * Used to create cookies with proper path.
  * If you don't use root folder of your site, put the extension here:
    * If you use something like `https://dssoftware.ru/login` - put `/login` here
    * If you use something like `https://dssoftware.ru/` - leave `/`
    * If you use something like `https://example.dssoftware.ru/login` - put `/login` here
	
* $session_length
  * Defines the length of a random_session_id. If too small, RSID will duplicate. If too big, might cause some performance issues.
    * Optimal value - `32`
	
* $service_key
  * Used to verify data obtained from external sources - use a moderately long one.
* $encryption_key
  * Used to encrypt data that cannot be stored for some reason.
  
* $database
  * Fill that array with data obtained from your database provider.
  
* $email_info
  * Fill that array with data you want to be shown in GUI.
  
* $email_settings
  * Fill that array with data obtained from your email host provider.
  
* $enable_creation
  * If `true`, API will allow to create projects, doesn't affect admins.
* $integrations_limit
  * Sets the maximum amount of integrations that could be created. Doesn't affect admins.
* $allowed_admins
  * Gives administrative permissions to specific users.
  * WARNING! Do not give admin permissions to accounts without a reason.
    
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

## Contributing & Issues
When contributing changes to the project, please provide as much detail on the changes. Malicious or meaningless contributions won't be accepted.
Please, if you found an issue in ULS, create a GitHub issue.
Besides, you can contact DS Software team: https://dssoftware.ru/about/
