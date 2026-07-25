<?php

namespace BadBehaviour\Challenge;

use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;

class RecaptchaChallenge implements ChallengeInterface
{
    private Configuration $config;

    public function __construct(Configuration $config, ?AdapterInterface $adapter = null)
    {
        $this->config = $config;
    }

    public function verify(RequestPackage $package): bool
    {
        $response = $_POST['g-recaptcha-response'] ?? $_GET['g-recaptcha-response'] ?? '';
        if (!$response) return false;

        $secret = $this->config->challenge_secret_key;
        if (!$secret) return false;

        $data = [
            'secret' => $secret,
            'response' => $response,
            'remoteip' => $package->ip,
        ];

        $result = $this->http_post('https://www.google.com/recaptcha/api/siteverify', $data);

        $min_score = $this->config->recaptcha_min_score;
        return ($result['success'] ?? false) && ($result['score'] ?? 0) >= $min_score;
    }

    public function render(string $action_url): string
    {
        $site_key = $this->config->challenge_site_key;

        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Security Check</title>
	<style>
		body { font-family: system-ui, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }
		.card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; max-width: 400px; }
	</style>
</head>
<body>
	<div class="card">
		<h2>Security Check</h2>
		<form method="POST" action="{$action_url}" id="form">
			<button class="g-recaptcha"
			        data-sitekey="{$site_key}"
			        data-callback="onSubmit"
			        data-action="verify"
			        style="padding: 0.75rem 1.5rem; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer;">
				Verify
			</button>
			<input type="hidden" name="g-recaptcha-response" id="g-recaptcha-response">
		</form>
	</div>
	<script src="https://www.google.com/recaptcha/api.js?render={$site_key}"></script>
	<script>
		function onSubmit(token) {
			document.getElementById('g-recaptcha-response').value = token;
			document.getElementById('form').submit();
		}
		grecaptcha.ready(function() {
			grecaptcha.execute('{$site_key}', {action: 'verify'}).then(onSubmit);
		});
	</script>
</body>
</html>
HTML;
    }

    private function http_post(string $url, array $data): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($data),
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
        return json_decode($response, true) ?? [];
    }
}
