<?php
// Copy this file to config.php (same folder) on the server and fill in the three values.
// config.php is listed in .gitignore so your real values never reach GitHub.
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

    // Optional. Email alerts, sent for every sign-in, every failed attempt (wrong master password, PIN or
    // authenticator code), new devices, and every security change. Leave out to send no email.
    // The address stays in this file on the server and never reaches GitHub.
    // 'alert_email' => 'you@example.com',
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
