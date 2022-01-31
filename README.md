# DS Software ULS

This is a PHP implementation of a login system for DS Software.

## Usage

DS Software ULS is a standalone login system, so you don't have to install anything else.
### Configuration
The only file you need to modify is config.php.
* Configuration Steps:
  * Edit $allowed_origins
    * Allowed origins specify the hosts that are allowed to bypass CORS policy.
  * Edit $login_site
    * Login site stands for a URL of index page of ULS.
  * Change Secured Values
    * $service_key is a secure key that allows ULS to verify data from external sources.
    * $encryption_key is a secure key that is used to encrypt user password while checking email during registration.
    * $service_oauth is a secure key that is used to sign a User Verification Code.
    * $service_verification is a secure key that is used to sign a User Verification Code.
  * Insert Database Login Info
    * $database is used to connect to a MySQL database.
  * Insert Email Login Info
    * $email_settings are used to send service emails to users.
  * Modify Projects
    * $projects are used as a list of possible projects that allow ULS authentication.
    
### Database Configuration
There is a Database Dump inside a .database folder. Use database_setup.sql as an Import File in PHPMyAdmin or just execute the SQL commands inside the file.

## License
This project is licensed under CC0 License.

## Credits
There is a list of all libraries that are used in ULS.
* ApMailer (https://github.com/anton-pribora/ApMailer)
* Browser Libs (https://www.php.net/manual/en/function.get-browser.php#101125)
* PHPQRCode (https://phpqrcode.sourceforge.net/index.php)
* PHP TOTP (https://github.com/lfkeitel/php-totp/)

## Contributing & Issues
When contributing changes to the project, please provide as much detail on the changes. Malicious or meaningless contributions won't be accepted.
Please, if you found an issue in ULS, create a GitHub issue.
Besides, you can contact DS Software team: https://ds-software.xyz/about/
