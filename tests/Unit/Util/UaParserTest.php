<?php

namespace BadBehaviour\Tests\Unit\Util;

use BadBehaviour\Util\UaParser;
use PHPUnit\Framework\TestCase;

class UaParserTest extends TestCase
{
    public function test_parse_chrome(): void
    {
        $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
        $result = UaParser::parse($ua);

        $this->assertEquals('Chrome', $result['browser']['name']);
        $this->assertEquals('Windows', $result['os']['name']);
        $this->assertEquals('desktop', $result['device']['type']);
        $this->assertFalse($result['device']['is_bot']);
        $this->assertFalse($result['device']['is_http_tool']);
    }

    public function test_parse_firefox(): void
    {
        $ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0';
        $result = UaParser::parse($ua);

        $this->assertEquals('Firefox', $result['browser']['name']);
        $this->assertEquals('Linux', $result['os']['name']);
        $this->assertFalse($result['device']['is_bot']);
    }

    public function test_parse_googlebot(): void
    {
        $ua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
        $result = UaParser::parse($ua);

        $this->assertTrue($result['device']['is_bot']);
        $this->assertEquals('bot', $result['device']['type']);
    }

    public function test_parse_curl(): void
    {
        $ua = 'curl/8.18.0';
        $result = UaParser::parse($ua);

        $this->assertEquals('http_tool', $result['device']['type']);
        $this->assertFalse($result['device']['is_bot']);
        $this->assertTrue($result['device']['is_http_tool']);
    }

    public function test_parse_wget(): void
    {
        $ua = 'Wget/1.21.4';
        $result = UaParser::parse($ua);

        $this->assertEquals('http_tool', $result['device']['type']);
        $this->assertFalse($result['device']['is_bot']);
        $this->assertTrue($result['device']['is_http_tool']);
    }

    public function test_parse_python_requests(): void
    {
        $ua = 'python-requests/2.31.0';
        $result = UaParser::parse($ua);

        $this->assertEquals('http_tool', $result['device']['type']);
        $this->assertFalse($result['device']['is_bot']);
        $this->assertTrue($result['device']['is_http_tool']);
    }

    public function test_is_bot(): void
    {
        $this->assertTrue(UaParser::is_bot('Mozilla/5.0 (compatible; Googlebot/2.1)'));
        $this->assertTrue(UaParser::is_bot('Mozilla/5.0 (compatible; bingbot/2.0)'));
        $this->assertTrue(UaParser::is_bot('Mozilla/5.0 (compatible; SemrushBot/7~bl)'));

        // HTTP tools are NOT bots
        $this->assertFalse(UaParser::is_bot('curl/8.18.0'));
        $this->assertFalse(UaParser::is_bot('Wget/1.21.4'));
        $this->assertFalse(UaParser::is_bot('python-requests/2.31.0'));
        $this->assertFalse(UaParser::is_bot('Mozilla/5.0 Chrome/120.0.0.0'));
    }

    public function test_is_http_tool(): void
    {
        $this->assertTrue(UaParser::is_http_tool('curl/8.18.0'));
        $this->assertTrue(UaParser::is_http_tool('Wget/1.21.4'));
        $this->assertTrue(UaParser::is_http_tool('python-requests/2.31.0'));
        $this->assertTrue(UaParser::is_http_tool('Go-http-client/1.1'));
        $this->assertTrue(UaParser::is_http_tool('Java/17.0.1'));
        $this->assertTrue(UaParser::is_http_tool('okhttp/4.10.0'));

        $this->assertFalse(UaParser::is_http_tool('Mozilla/5.0 Chrome/120.0.0.0'));
        $this->assertFalse(UaParser::is_http_tool('Mozilla/5.0 (compatible; Googlebot/2.1)'));
    }

    public function test_parse_mobile(): void
    {
        $ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15';
        $result = UaParser::parse($ua);

        $this->assertTrue($result['device']['is_mobile']);
        $this->assertEquals('mobile', $result['device']['type']);
    }

    public function test_parse_tablet(): void
    {
        $ua = 'Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15';
        $result = UaParser::parse($ua);

        $this->assertTrue($result['device']['is_tablet']);
        $this->assertEquals('tablet', $result['device']['type']);
    }

    public function test_parse_headless_chrome(): void
    {
        $ua = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36';
        $result = UaParser::parse($ua);

        $this->assertTrue($result['device']['is_bot']);
        $this->assertEquals('bot', $result['device']['type']);
    }
}
