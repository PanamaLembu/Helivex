<?php

//Begin Really Simple Security session cookie settings
@ini_set('session.cookie_httponly', true);
@ini_set('session.cookie_secure', true);
@ini_set('session.use_only_cookies', true);
//END Really Simple Security cookie settings
//Begin Really Simple Security key
define('RSSSL_KEY', 'yFCSkdZXzNENnm0sGcdrfMv0i0f40piVnC3sQJjCGQnTYSpb1nwxkHdXXdk9yHtM');
//END Really Simple Security key
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * Localized language
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'dbs5wcyjgjkgui' );

/** Database username */
define( 'DB_USER', 'u9gfuhguyt1tp' );

/** Database password */
define( 'DB_PASSWORD', 'ahlmoftdasgz' );

/** Database hostname */
define( 'DB_HOST', '127.0.0.1' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',          'yh*2,@_yA$G()b`x1mJ8r@ZaK~xqCVA7t^+/Swb4fx3&-y[6K2/7A&5^yPxOj|ay' );
define( 'SECURE_AUTH_KEY',   '5LZS!XP0[MA__?G,PDfciBHYd,H=MJI{|JTl.s=Ki@WYPp9O29A|OXkAX&+0JkG{' );
define( 'LOGGED_IN_KEY',     'qp7;J:LcUvJe_dIA,oiM+Rg$-g L)RbN5jkH8Uu%}=@l=&7SX`/MKf+e*h_QD&D$' );
define( 'NONCE_KEY',         ')l8~jE~8?GSg?I0.B6%Q!I=}${,JelzW0`|b.^x5s%M4?~Ih%((Ej,/Yz/2V=Y@C' );
define( 'AUTH_SALT',         'U@ST,YA~G5C2Oko58f+q!&Q-:;_AZ^T&`ht*]*K/9od*zl>53r][tZdlkpt{2E27' );
define( 'SECURE_AUTH_SALT',  'rA$o&{T&lT^@_f~[D1Th):coSMWH,;tQed]-5ur|:Hf]d&8H:8OpY-L%1B,*yb0/' );
define( 'LOGGED_IN_SALT',    's,IZ|r<?ylX*(d#P]%D5Ewm4n9>a)[SeQW4ZP]W7^cs`d)LU<t4KYwJU4;Lk%abB' );
define( 'NONCE_SALT',        't(RXXhWGC*8[2D6?OQ<-Hr;BER592@%w)kpgDRD6Go6pON>E>Y%U;$Grd-^lcX)6' );
define( 'WP_CACHE_KEY_SALT', 'lNl] gxM{DS*4Wz>>=Sqa}x0BvnVWEc7,AZ08xnP<FRY a`n:NT#lTl<!252{NWk' );


/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'lqj_';


/* Add any custom values between this line and the "stop editing" line. */



/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
if ( ! defined( 'WP_DEBUG' ) ) {
	define( 'WP_DEBUG', false );
}

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
@include_once('/var/lib/sec/wp-settings-pre.php'); // Added by SiteGround WordPress management system
require_once ABSPATH . 'wp-settings.php';
@include_once('/var/lib/sec/wp-settings.php'); // Added by SiteGround WordPress management system
