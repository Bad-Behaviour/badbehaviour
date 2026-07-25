<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Util;

use BadBehaviour\Util\UaParser;
use PHPUnit\Framework\TestCase;

class UaParserTest extends TestCase
{
    public function test_parse_chrome_windows(): void
    {
        $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
        $result = UaParser::parse($ua);

        $this->assertEquals('Chrome', $result['browser']['name']);
        $this->assertEquals('120.0.0.0', $result['browser']['version']);
        $this->assertEquals(120, $result['browser']['major']);
        $this->assertEquals('Windows', $result['os']['name']);
        $this->assertEquals('desktop', $result['device']['type']);
        $this->assertEquals('blink', $result['engine']['name']);
    }

    public function test_parse_firefox_linux(): void
    {
        $ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0';
        $result = UaParser::parse($ua);

        $this->assertEquals('Firefox', $result['browser']['name']);
        $this->assertEquals(121, $result['browser']['major']);
        $this->assertEquals('Linux', $result['os']['name']);
        $this->assertEquals('gecko', $result['engine']['name']);
    }

    public function test_parse_safari_macos(): void
    {
        $ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15';
        $result = UaParser::parse($ua);

        $this->assertEquals('Safari', $result['browser']['name']);
        $this->assertEquals('17.2', $result['browser']['version']);
        $this->assertEquals(17, $result['browser']['major']);
        $this->assertEquals('macOS', $result['os']['name']);
        $this->assertEquals('webkit', $result['engine']['name']);
    }

    public function test_parse_safari_ios(): void
    {
        $ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1';
        $result = UaParser::parse($ua);

        $this->assertEquals('Safari', $result['browser']['name']);
        $this->assertEquals('iOS', $result['os']['name']);
        $this->assertEquals('mobile', $result['device']['type']);
        $this->assertTrue($result['device']['is_mobile']);
    }

    public function test_parse_edge_windows(): void
    {
        $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0';
        $result = UaParser::parse($ua);

        $this->assertEquals('Edge', $result['browser']['name']);
        $this->assertEquals(120, $result['browser']['major']);
        $this->assertEquals('blink', $result['engine']['name']);
    }

    public function test_parse_googlebot(): void
    {
        $ua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
        $result = UaParser::parse($ua);

        $this->assertEquals('Unknown', $result['browser']['name']);
        $this->assertTrue($result['device']['is_bot']);
        $this->assertEquals('bot', $result['device']['type']);
    }

    public function test_parse_bingbot(): void
    {
        $ua = 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)';
        $result = UaParser::parse($ua);

        $this->assertTrue($result['device']['is_bot']);
    }

    public function test_parse_headless_chrome(): void
    {
        $ua = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36';
        $result = UaParser::parse($ua);

        $this->assertEquals('Chrome', $result['browser']['name']);
        $this->assertTrue($result['device']['is_bot']); // Headless detected as bot
    }

    public function test_parse_puppeteer(): void
    {
        $ua = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Puppeteer/21.0.0';
        $result = UaParser::parse($ua);

        $this->assertTrue($result['device']['is_bot']);
    }

    public function test_parse_curl(): void
    {
        $ua = 'curl/8.5.0';
        $result = UaParser::parse($ua);

        $this->assertEquals('Unknown', $result['browser']['name']);
        $this->assertEquals('bot', $result['device']['type']);
    }

    public function test_parse_empty(): void
    {
        $ua = '';
        $result = UaParser::parse($ua);

        $this->assertEquals('Unknown', $result['browser']['name']);
        $this->assertEquals('Unknown', $result['os']['name']);
        $this->assertEquals('desktop', $result['device']['type']);
    }

    public function test_is_bot(): void
    {
        $this->assertTrue(UaParser::is_bot('Mozilla/5.0 (compatible; Googlebot/2.1)'));
        $this->assertTrue(UaParser::is_bot('curl/7.68.0'));
        $this->assertFalse(UaParser::is_bot('Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0'));
    }

    public function test_is_mobile(): void
    {
        $this->assertTrue(UaParser::is_mobile('Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X)'));
        $this->assertFalse(UaParser::is_mobile('Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0'));
    }

    public function test_is_tablet(): void
    {
        $this->assertTrue(UaParser::is_tablet('Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X)'));
        $this->assertFalse(UaParser::is_tablet('Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0'));
    }

    public function test_get_browser_version(): void
    {
        $this->assertEquals('120.0.0.0', UaParser::get_browser_version('Chrome/120.0.0.0'));
        $this->assertEquals('121.0', UaParser::get_browser_version('Firefox/121.0'));
        $this->assertNull(UaParser::get_browser_version('Unknown'));
    }

    public function test_matches_bot_registry(): void
    {
        $patterns = ['Googlebot', 'Bingbot', 'Slurp'];
        $this->assertTrue(UaParser::matches_bot_registry('Googlebot/2.1', $patterns));
        $this->assertTrue(UaParser::matches_bot_registry('Mozilla/5.0 (compatible; bingbot/2.0)', $patterns));
        $this->assertFalse(UaParser::matches_bot_registry('Chrome/120.0.0.0', $patterns));
    }
}
