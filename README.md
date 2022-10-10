# Bad Behaviour

Bad Behavior prevents spammers from ever delivering their junk, and in many
cases, from ever reading your site in the first place.

## Description

Welcome to a whole new way of keeping your blog, forum, guestbook, wiki or
content management system free of link spam. Bad Behavior is a PHP-based
solution for blocking link spam and the robots which deliver it.

Thousands of sites large and small, trust Bad Behavior to help reduce
incoming link spam and malicious activity.

Bad Behavior complements other link spam solutions by acting as a gatekeeper,
preventing spammers from ever delivering their junk, and in many cases, from
ever reading your site in the first place. This keeps your site's load down,
makes your site logs cleaner, and can help prevent denial of service
conditions caused by spammers.

Bad Behavior also transcends other link spam solutions by working in a
completely different, unique way. Instead of merely looking at the content of
potential spam, Bad Behavior analyzes the delivery method as well as the
software the spammer is using. In this way, Bad Behavior can stop spam attacks
even when nobody has ever seen the particular spam before.

Bad Behavior is designed to work alongside existing spam prevention services
to increase their effectiveness and efficiency. Whenever possible, you should
run it in combination with a more traditional spam prevention service.

Bad Behavior works on, or can be adapted to, virtually any PHP-based Web
software package. Bad Behavior is available for many packages.

Installing and configuring Bad Behavior on most platforms is simple and takes
only a few minutes. In most cases, no configuration at all is needed. Simply
turn it on and stop worrying about spam!

The core of Bad Behavior is free software released under the GNU Lesser General
Public License, version 3, or at your option, any later version.

## Installation

Bad Behavior has been designed to install on each host software in the
manner most appropriate to each platform. It's usually sufficient to
follow the generic instructions for installing any plugin or extension
for your host software.

On MediaWiki, it is necessary to add a second line to LocalSettings.php
when installing the extension. Your LocalSettings.php should include
the following:

`	include_once( 'includes/DatabaseFunctions.php' );
	include( './extensions/Bad-Behavior/bad-behavior-mediawiki.php' );

For complete documentation and installation instructions, please visit
[User Guide](https://github.com/Bad-Behaviour/badbehaviour)

## Screenshots

1. Most of the time, only spammers see this. In the rare event a human
winds up here, a way out is provided. This may involve removing malicious
software from the user's computer, changing firewall settings or other simple
fixes which will immediately grant access again.

2. Bad Behavior's built in log viewer (WordPress) shows why requests were
blocked and allows you to click on any IP address, user-agent string or
block reason to filter results.

## Release Notes

### Bad Behavior 2.2 Known Issues

* Bad Behavior 2.2 requires MySQL 5.7 or later and PHP 8.0 or later.

* CloudFlare users must enable the Reverse Proxy option in Bad Behavior's
settings. See the documentation for further details.

* Bad Behavior is unable to protect internally cached pages on MediaWiki.
Only form submissions will be protected.

* On WordPress when using WP-Super Cache, Bad Behavior must be enabled in
WP-Super Cache's configuration in order to protect PHP Cached or Legacy
Cached pages. Bad Behavior cannot protect mod_rewrite cached (Super Cached)
pages.

