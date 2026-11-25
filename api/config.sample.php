<?php
// Copy this file to the server as config.php and fill in the three values.
// Best place: a folder named vault-data beside the website folder (for example /home/USER/vault-data/config.php),
// which the web server never serves. The API looks there first. A config.php in this api folder still works.
// Set its permissions to 600. config.php is listed in .gitignore so your real values never reach GitHub.
return [
    // Absolute path to a folder OUTSIDE the web root. The API refuses to run if it is inside it.
    // On cPanel this is usually /home/YOUR_CPANEL_USER/vault-data
    'data_dir' => '/home/CHANGE_ME/vault-data',

    // Long random string, 32+ characters. Generate one in the app's Generator tab.
    'server_secret' => 'CHANGE_ME',

    // Needed to create an account, 12+ characters. Share only with people you want on your server.
    'invite_code' => 'CHANGE_ME',

    // Set to false once your accounts exist to close sign-ups completely.
    'allow_registration' => true,

    // Optional. The owner sees failed attempts against every username in the access log.
    // Leave this out and the first account created on the server is the owner.
    // 'owner' => 'yourusername',

    // Optional. The access log shows a city and country for each address by asking this service.
    // Set to false to switch that off, so addresses are never sent to anyone.
    // 'geo_url' => 'https://free.freeipapi.com/api/v1/json/{ip}',

    // Optional. Email alerts. Leave out to send no email. By default they cover only what matters: the vault
    // opened on a new device, a changed master password, a recovery, two-factor turned off, the recovery key
    // removed, and sign-in or recovery blocked after repeated wrong tries. The Access log keeps everything else.
    // The address stays in this file on the server and never reaches GitHub.
    // 'alert_email' => 'you@example.com',
    // Optional. 'all' sends an email for every event in the Access log.
    // 'alert_level' => 'all',
    // Optional. Events to leave out of the emails, by their log name. For example, to skip ordinary sign-ins:
    // 'alert_skip' => ['login_ok'],
    // Optional. Adds an "Open Vault" button to the emails. Must be the https address of your own vault.
    // The address is printed under the button so it can be checked before signing in.
    // 'alert_link' => 'https://vault.example.com',
    // Optional. Time zone for the time shown in the emails. Defaults to UTC.
    // 'alert_tz' => 'America/Toronto',
    // Optional sender address. Defaults to vault@ your site's domain.
    // 'alert_from' => 'vault@example.com',
];
