<?php

namespace BadBehaviour\Challenge;

use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;

class BuiltinChallenge implements ChallengeInterface
{
	private Configuration $config;
	private AdapterInterface $adapter;

	public function __construct(Configuration $config, ?AdapterInterface $adapter = null)
	{
		$this->config = $config;
		$this->adapter = $adapter ?? new \BadBehaviour\Adapter\GenericAdapter();
	}

	public function verify(RequestPackage $package): bool
	{
		// Check both POST body and GET params
		$token = $package->request_entity['bb_challenge_token'] ?? $_POST['bb_challenge_token'] ?? $_GET['bb_challenge_token'] ?? '';
		if (!$token) return false;

		$key = "challenge:{$package->ip}:{$token}";
		$issued = $this->adapter->get_counter($key);

		if ($issued > 0) {
			$this->adapter->delete($key);
			return true;
		}
		return false;
	}

	public function render(string $action_url): string
	{
		$package = $this->get_current_package();
		$is_mobile = $package->ua_is_mobile ?? false;
		$is_bot = $package->ua_is_bot ?? false;

		$token = bin2hex(random_bytes(16));
		$difficulty = $is_mobile ? 5000 : 10000;

		$key = "challenge:{$_SERVER['REMOTE_ADDR']}:{$token}";
		$this->adapter->increment_counter($key, 300);

		$message = $is_bot
			? 'Automated access detected. Please verify you are human.'
			: 'Please wait while we verify your browser...';

		return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Security Check</title>
	<style>
		body { font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }
		.card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; max-width: 400px; width: 90%; }
		.progress { width: 100%; height: 4px; background: #eee; border-radius: 2px; overflow: hidden; margin: 1.5rem 0; }
		.bar { width: 0%; height: 100%; background: #0066cc; transition: width 0.1s linear; }
		@media (max-width: 480px) { .card { padding: 1.5rem; } }
	</style>
</head>
<body>
	<div class="card">
		<h2>Security Check</h2>
		<p>{$message}</p>
		<div class="progress"><div class="bar" id="bar"></div></div>
		<form method="POST" action="{$action_url}" id="form">
			<input type="hidden" name="bb_challenge_token" value="{$token}">
		</form>
	</div>
	<script>
		(function() {
			var difficulty = {$difficulty};
			var start = Date.now();
			var target = start + difficulty;
			var bar = document.getElementById('bar');

			function work() {
				var now = Date.now();
				var progress = Math.min(100, ((now - start) / difficulty) * 100);
				bar.style.width = progress + '%';

				if (now < target) {
					requestAnimationFrame(work);
				} else {
					document.getElementById('form').submit();
				}
			}
			requestAnimationFrame(work);
		})();
	</script>
</body>
</html>
HTML;
	}

	private function get_current_package(): RequestPackage
	{
		return new RequestPackage(
			ip: $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1',
			headers: [],
			headers_mixed: [],
			request_method: 'GET',
			request_uri: '/',
			server_protocol: 'HTTP/1.1',
			request_entity: [],
			user_agent: $_SERVER['HTTP_USER_AGENT'] ?? '',
		);
	}
}
