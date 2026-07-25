<?php

namespace BadBehaviour\Challenge;

use BadBehaviour\Configuration;
use BadBehaviour\Core\Interfaces\AdapterInterface;
use BadBehaviour\Util\RequestPackage;

class HCaptchaChallenge implements ChallengeInterface
{
    private Configuration $config;

    public function __construct(Configuration $config, ?AdapterInterface $adapter = null)
    {
        $this->config = $config;
    }

    public function verify(RequestPackage $package): bool
    {
        $response = $_POST['h-captcha-response'] ?? $_GET['h-captcha-response'] ?? '';
        if (!$response) return false;

        $secret = $this->config->challenge_secret_key;
        if (!$secret) return false;

        $data = [
            'secret' => $secret,
            'response' => $response,
            'remoteip' => $package->ip,
        ];

        $result = $this->http_post('https://hcaptcha.com/siteverify', $data);
        return $result['success'] ?? false;
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
		<form method="POST" action="{$action_url}">
			<div class="h-captcha" data-sitekey="{$site_key}"></div>
			<button type="submit" style="margin-top: 1rem; padding: 0.75rem 1.5rem; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer;">Verify</button>
		</form>
	</div>
	<script src="https://js.hcaptcha.com/1/api.js" async defer></script>
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
