<?php

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Core;

use BadBehaviour\Core\EnforcementAction;
use BadBehaviour\Core\Result;
use BadBehaviour\Core\ResultCode;
use BadBehaviour\Util\RequestPackage;
use PHPUnit\Framework\TestCase;

class ResultTest extends TestCase
{
    private RequestPackage $pkg;

    protected function setUp(): void
    {
        $this->pkg = new RequestPackage(
            ip: '192.168.1.1',
            headers: [],
            headers_mixed: [],
            request_method: 'GET',
            request_uri: '/test',
            server_protocol: 'HTTP/1.1',
            request_entity: [],
            user_agent: 'Test/1.0'
        );
    }

    // ====================================================================
    // FACTORY METHODS — your existing tests, preserved verbatim
    // ====================================================================

    public function test_allow(): void
    {
        $result = Result::allow();

        $this->assertTrue($result->is_allowed());
        $this->assertFalse($result->is_blocked());
        $this->assertFalse($result->requires_challenge());
        $this->assertEquals(200, $result->http_status());
        $this->assertEquals(ResultCode::ALLOWED, $result->code);
    }

    public function test_block(): void
    {
        $result = Result::block(
            ResultCode::BLOCKED_BOT,
            'Test block',
            $this->pkg,
            ['test' => 'data']
        );

        $this->assertFalse($result->is_allowed());
        $this->assertTrue($result->is_blocked());
        $this->assertFalse($result->requires_challenge());
        $this->assertEquals(403, $result->http_status());
        $this->assertEquals(ResultCode::BLOCKED_BOT, $result->code);
        $this->assertEquals('Test block', $result->message);
        $this->assertEquals($this->pkg, $result->package);
        $this->assertEquals(['test' => 'data'], $result->metadata);
        $this->assertNotNull($result->support_key);
    }

    public function test_challenge(): void
    {
        $result = Result::challenge(
            ResultCode::CHALLENGE_REQUIRED,
            'Test challenge',
            $this->pkg
        );

        $this->assertFalse($result->is_allowed());
        $this->assertFalse($result->is_blocked());
        $this->assertTrue($result->requires_challenge());
        $this->assertEquals(403, $result->http_status());
        $this->assertEquals(ResultCode::CHALLENGE_REQUIRED, $result->code);
    }

    public function test_to_array(): void
    {
        $result = Result::block(ResultCode::BLOCKED_BOT, 'Test', $this->pkg);
        $array = $result->to_array();

        $this->assertArrayHasKey('code', $array);
        $this->assertArrayHasKey('message', $array);
        $this->assertArrayHasKey('support_key', $array);
        $this->assertArrayHasKey('http_status', $array);
        $this->assertArrayHasKey('metadata', $array);
        $this->assertEquals('blocked.bot', $array['code']);
        $this->assertEquals(403, $array['http_status']);
    }

    // ====================================================================
    // NEW: is_actionable() — the routing predicate hosts SHOULD use
    // ====================================================================

    public function testIsActionableTrueForEnforcedBlock(): void
    {
        $r = Result::block(ResultCode::BLOCKED_MALICIOUS_UA, 'test', $this->pkg);

        $this->assertTrue($r->is_actionable());
        $this->assertTrue($r->is_enforced_block());
        $this->assertFalse($r->is_monitored());
        $this->assertFalse($r->reaches_application());
    }

    public function testIsActionableTrueForEnforcedChallenge(): void
    {
        $r = Result::challenge(ResultCode::CHALLENGE_REQUIRED, 'test', $this->pkg);

        $this->assertTrue($r->is_actionable());
        $this->assertTrue($r->is_enforced_block());
    }

    public function testIsActionableFalseForAllowed(): void
    {
        $r = Result::allow($this->pkg);

        $this->assertFalse($r->is_actionable());
        $this->assertFalse($r->is_enforced_block());
        $this->assertFalse($r->is_monitored());
        $this->assertTrue($r->reaches_application());
    }

    /**
     * THE REGRESSION TEST for the WackoWiki production crash.
     *
     * A MONITORED result MUST return FALSE for is_actionable()
     * so the host integration doesn't call handle_result() on it.
     */
    public function testIsActionableFalseForMonitored(): void
    {
        $blocked = Result::block(
            ResultCode::BLOCKED_BOT,
            'would-have-blocked',
            $this->pkg,
            ['bot_name' => 'TestBot']
        );
        $monitored = Result::monitored_from($blocked);

        $this->assertSame(ResultCode::MONITORED_BOT, $monitored->code);
        $this->assertSame(EnforcementAction::MONITORED, $monitored->enforcement);

        $this->assertFalse(
            $monitored->is_actionable(),
            'Monitored result must NOT be actionable — handle_result() would be misuse'
        );
        $this->assertFalse($monitored->is_enforced_block());
        $this->assertTrue($monitored->is_monitored());
        $this->assertTrue($monitored->reaches_application());
    }

    // ====================================================================
    // NEW: reaches_application() vs is_purely_allowed() vs is_allowed()
    // ====================================================================

    public function testIsAllowedIsStrict(): void
    {
        // The bug-causing semantic: is_allowed() returns FALSE for MONITORED
        // even though the request reaches the application.
        $blocked = Result::block(ResultCode::BLOCKED_BOT, 'x', $this->pkg);
        $monitored = Result::monitored_from($blocked);

        $this->assertFalse(
            $monitored->is_allowed(),
            'is_allowed() is strict — returns FALSE for MONITORED. '
            . 'Use is_actionable() or reaches_application() instead.'
        );
    }

    public function testReachesApplicationForAllowed(): void
    {
        $this->assertTrue(Result::allow($this->pkg)->reaches_application());
    }

    public function testReachesApplicationForMonitored(): void
    {
        $blocked = Result::block(ResultCode::BLOCKED_BOT, 'x', $this->pkg);
        $monitored = Result::monitored_from($blocked);

        $this->assertTrue(
            $monitored->reaches_application(),
            'Monitored results reach the application (enforcement=monitored)'
        );
    }

    public function testReachesApplicationFalseForEnforced(): void
    {
        $blocked = Result::block(ResultCode::BLOCKED_BOT, 'x', $this->pkg);
        $this->assertFalse($blocked->reaches_application());
    }

    public function testIsPurelyAllowedTrueOnlyForAllowed(): void
    {
        $this->assertTrue(Result::allow($this->pkg)->is_purely_allowed());

        $blocked = Result::block(ResultCode::BLOCKED_BOT, 'x', $this->pkg);
        $monitored = Result::monitored_from($blocked);

        $this->assertFalse($blocked->is_purely_allowed());
        $this->assertFalse($monitored->is_purely_allowed());
    }

    // ====================================================================
    // NEW: monitored_from() preserves metadata
    // ====================================================================

    public function testMonitoredFromPreservesOriginalMetadata(): void
    {
        $blocked = Result::block(
            ResultCode::BLOCKED_BOT,
            'would-block',
            $this->pkg,
            ['bot_name' => 'TestBot', 'bot_category' => 'search_engine']
        );
        $monitored = Result::monitored_from($blocked);

        $this->assertSame('TestBot', $monitored->metadata['bot_name']);
        $this->assertSame('search_engine', $monitored->metadata['bot_category']);
        $this->assertSame('blocked.bot', $monitored->metadata['original_code']);
        $this->assertTrue($monitored->metadata['monitor_only']);
        $this->assertEquals('would-block', $monitored->message);
        $this->assertSame($blocked->support_key, $monitored->support_key);
    }

    public function testMonitoredFromUnmonitorableCodeKeepsCode(): void
    {
        $allowed = Result::allow($this->pkg);
        $monitored = Result::monitored_from($allowed);

        $this->assertSame(ResultCode::ALLOWED, $monitored->code);
        $this->assertSame(EnforcementAction::MONITORED, $monitored->enforcement);
    }

    // ====================================================================
    // NEW: to_array() includes new fields
    // ====================================================================

    public function testToArrayIncludesIsActionableForBlock(): void
    {
        $blocked = Result::block(ResultCode::BLOCKED_BOT, 'x', $this->pkg);
        $arr = $blocked->to_array();

        $this->assertArrayHasKey('is_actionable', $arr);
        $this->assertTrue($arr['is_actionable']);
    }

    public function testToArrayForMonitored(): void
    {
        $blocked = Result::block(ResultCode::BLOCKED_BOT, 'x', $this->pkg);
        $monitored = Result::monitored_from($blocked);
        $arr = $monitored->to_array();

        $this->assertFalse($arr['is_actionable']);
        $this->assertTrue($arr['is_monitored']);
        $this->assertSame('monitored', $arr['enforcement']);
        $this->assertSame('blocked.bot', $arr['original_code']);
    }

    // ====================================================================
    // NEW: ResultCode::to_monitored() coverage
    // ====================================================================

    /**
     * @dataProvider blockedToMonitoredProvider
     */
    public function testToMonitoredConvertsBlockedCodes(
        ResultCode $blocked,
        ResultCode $expectedMonitored
    ): void {
        $this->assertSame($expectedMonitored, $blocked->to_monitored());
    }

    public static function blockedToMonitoredProvider(): array
    {
        return [
            'bot'           => [ResultCode::BLOCKED_BOT,            ResultCode::MONITORED_BOT],
            'ai_crawler'    => [ResultCode::BLOCKED_AI_CRAWLER,     ResultCode::MONITORED_AI_CRAWLER],
            'seo_crawler'   => [ResultCode::BLOCKED_SEO_CRAWLER,    ResultCode::MONITORED_SEO_CRAWLER],
            'malicious_ua'  => [ResultCode::BLOCKED_MALICIOUS_UA,   ResultCode::MONITORED_MALICIOUS_UA],
            'attack'        => [ResultCode::BLOCKED_ATTACK_PATTERN, ResultCode::MONITORED_ATTACK_PATTERN],
            'dnsbl'         => [ResultCode::BLOCKED_DNSBL,          ResultCode::MONITORED_DNSBL],
            'httpbl'        => [ResultCode::BLOCKED_HTTPBL,         ResultCode::MONITORED_HTTPBL],
            'behavioral'    => [ResultCode::BLOCKED_BEHAVIORAL,     ResultCode::MONITORED_BEHAVIORAL],
            'fingerprint'   => [ResultCode::BLOCKED_FINGERPRINT,    ResultCode::MONITORED_FINGERPRINT],
            'rate_limit'    => [ResultCode::BLOCKED_RATE_LIMIT,     ResultCode::MONITORED_RATE_LIMIT],
            'custom_rule'   => [ResultCode::BLOCKED_CUSTOM_RULE,    ResultCode::MONITORED_CUSTOM_RULE],
            'geoip'         => [ResultCode::BLOCKED_GEOIP,          ResultCode::MONITORED_GEOIP],
            'challenge'     => [ResultCode::CHALLENGE_REQUIRED,     ResultCode::MONITORED_CHALLENGE],
        ];
    }

    public function testToMonitoredReturnsNullForUnmonitorable(): void
    {
        $this->assertNull(ResultCode::ALLOWED->to_monitored());
        $this->assertNull(ResultCode::ERROR_INTERNAL->to_monitored());
        $this->assertNull(ResultCode::ERROR_CONFIGURATION->to_monitored());
        $this->assertNull(ResultCode::CHALLENGE_FAILED->to_monitored());

        // Already-monitored codes have no further demotion
        $this->assertNull(ResultCode::MONITORED_BOT->to_monitored());
        $this->assertNull(ResultCode::MONITORED_CHALLENGE->to_monitored());
    }

    public function testIsBlockedTrueForBlockedAndChallenge(): void
    {
        $this->assertTrue(ResultCode::BLOCKED_BOT->is_blocked());
        $this->assertTrue(ResultCode::BLOCKED_AI_CRAWLER->is_blocked());
        $this->assertFalse(ResultCode::BLOCKED_BOT->requires_challenge());
        $this->assertTrue(ResultCode::CHALLENGE_REQUIRED->requires_challenge());
    }

    public function testIsMonitoredOnlyForMonitoredCodes(): void
    {
        $this->assertTrue(ResultCode::MONITORED_BOT->is_monitored());
        $this->assertFalse(ResultCode::BLOCKED_BOT->is_monitored());
        $this->assertFalse(ResultCode::ALLOWED->is_monitored());
    }

    public function testHttpStatusForMonitoredCodes(): void
    {
        // Monitored codes never reach the wire — they flow through to the app
        // which returns 200. The 403 fallback only matters if a monitored
        // result accidentally leaks into handle_result().
        $this->assertSame(403, ResultCode::MONITORED_BOT->http_status());
        $this->assertSame(200, ResultCode::ALLOWED->http_status());
        $this->assertSame(429, ResultCode::BLOCKED_RATE_LIMIT->http_status());
        $this->assertSame(500, ResultCode::ERROR_INTERNAL->http_status());
    }
}
