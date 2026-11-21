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
];
