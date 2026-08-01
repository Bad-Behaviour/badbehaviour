<?php
// tests/Unit/Bot/RegistryTest.php - 3.1 with new categories

declare(strict_types=1);

namespace BadBehaviour\Tests\Unit\Bot;

use BadBehaviour\Bot\Registry;
use BadBehaviour\Bot\BotCategory;
use BadBehaviour\Bot\BotAction;
use PHPUnit\Framework\TestCase;

class RegistryTest extends TestCase
{
	public function test_all_returns_all_categories(): void
	{
		$all = Registry::all();

		$this->assertIsArray($all);
		$this->assertGreaterThan(50, count($all), 'Should have 50+ bots after 3.1 expansion');

		$categories = array_map(fn($bot) => $bot->category, $all);

		// Original categories
		$this->assertContains(BotCategory::SEARCH_ENGINE, $categories);
		$this->assertContains(BotCategory::AI_CRAWLER, $categories);
		$this->assertContains(BotCategory::SOCIAL_CRAWLER, $categories);
		$this->assertContains(BotCategory::SEO_CRAWLER, $categories);
		$this->assertContains(BotCategory::ARCHIVE_CRAWLER, $categories);
		$this->assertContains(BotCategory::MONITORING, $categories);

		// NEW categories
		$this->assertContains(BotCategory::FEED_READER, $categories, 'Missing FEED_READER category');
		$this->assertContains(BotCategory::SHOPPING_CRAWLER, $categories, 'Missing SHOPPING_CRAWLER category');
		$this->assertContains(BotCategory::CLOUD_INFRASTRUCTURE, $categories, 'Missing CLOUD_INFRASTRUCTURE category');
		$this->assertContains(BotCategory::SECURITY_SCANNER, $categories, 'Missing SECURITY_SCANNER category');
	}

	public function test_search_engines_have_required_fields(): void
	{
		$engines = Registry::search_engines();
		$this->assertGreaterThanOrEqual(20, count($engines), 'Should have 20+ search engines after regional additions');

		foreach ($engines as $id => $bot) {
			$this->assertEquals($id, $bot->id);
			$this->assertNotEmpty($bot->name);
			$this->assertNotEmpty($bot->user_agent_patterns);
			$this->assertEquals(BotCategory::SEARCH_ENGINE, $bot->category);
			$this->assertNotNull($bot->robots_txt_token);
		}
	}

	public function test_ai_crawler_actions_match_intent(): void
	{
		$crawlers = Registry::ai_crawlers();
		$this->assertEquals(BotAction::CHALLENGE, $crawlers['gptbot']->default_action);
		$this->assertEquals(BotAction::BLOCK, $crawlers['brightdata']->default_action,
			'BrightData residential proxy must default to BLOCK');
	}

	public function test_seo_crawler_actions_vary(): void
	{
		$crawlers = Registry::seo_crawlers();
		// Siteimprove is allowed (accessibility auditor, low-risk)
		$this->assertEquals(BotAction::ALLOW, $crawlers['siteimprove']->default_action);
		// Semrush is challenged (most SEO crawlers)
		$this->assertEquals(BotAction::CHALLENGE, $crawlers['semrush']->default_action);
	}

    public function test_monitoring_bots_allowed(): void
    {
        $monitoring = Registry::monitoring();

        foreach ($monitoring as $bot) {
            $this->assertEquals(BotCategory::MONITORING, $bot->category);
            $this->assertEquals(BotAction::ALLOW, $bot->default_action);
        }
    }

    public function test_googlebot_has_ip_ranges(): void
    {
        $engines = Registry::search_engines();
        $googlebot = $engines['googlebot'] ?? null;

        $this->assertNotNull($googlebot);
        $this->assertNotEmpty($googlebot->ip_ranges);
        $this->assertTrue($googlebot->verify_dns);
        $this->assertEquals('googlebot.com', $googlebot->dns_suffix);
    }

    public function test_gptbot_has_ip_ranges(): void
    {
        $crawlers = Registry::ai_crawlers();
        $gptbot = $crawlers['gptbot'] ?? null;

        $this->assertNotNull($gptbot);
        $this->assertNotEmpty($gptbot->ip_ranges);
        $this->assertTrue($gptbot->verify_dns);
        $this->assertEquals('openai.com', $gptbot->dns_suffix);
    }

    public function test_new_regional_search_engines(): void
    {
    	$engines = Registry::search_engines();

    	// P0 regional engines
    	$this->assertArrayHasKey('coccoc', $engines, 'Missing Cốc Cốc (Vietnam)');
    	$this->assertArrayHasKey('mailru', $engines, 'Missing Mail.ru (Russia)');
    	$this->assertArrayHasKey('petal', $engines, 'Missing Petal (Huawei, promoted)');
    	$this->assertArrayHasKey('zum', $engines, 'Missing Zum (Korea)');
    }

    public function test_ai_crawlers_include_new_entrants(): void
    {
    	$crawlers = Registry::ai_crawlers();
    	$this->assertGreaterThanOrEqual(15, count($crawlers));

    	$this->assertArrayHasKey('amazon_ai', $crawlers);
    	$this->assertArrayHasKey('semantic_scholar', $crawlers);
    	$this->assertArrayHasKey('diffbot', $crawlers);
    	$this->assertArrayHasKey('brightdata', $crawlers);

    	// Brightdata default action should be BLOCK (residential proxy = dangerous)
    	$this->assertEquals(BotAction::BLOCK, $crawlers['brightdata']->default_action);
    }

    public function test_social_crawlers_include_asian_platforms(): void
    {
    	$social = Registry::social_crawlers();

    	$this->assertArrayHasKey('kakao', $social, 'Missing Kakao (Korea #1 messenger)');
    	$this->assertArrayHasKey('line', $social, 'Missing LINE (JP/TW/TH)');
    	$this->assertArrayHasKey('wechat', $social, 'Missing WeChat (China)');
    	$this->assertArrayHasKey('notion', $social, 'Missing Notion (link previews)');
    }

    public function test_feed_readers_exist_and_allow(): void
    {
    	$feeds = Registry::feed_readers();
    	$this->assertNotEmpty($feeds);
    	$this->assertArrayHasKey('feedly', $feeds);
    	$this->assertArrayHasKey('apple_news', $feeds);
    	$this->assertArrayHasKey('google_news', $feeds);

    	foreach ($feeds as $bot) {
    		$this->assertEquals(BotCategory::FEED_READER, $bot->category);
    		$this->assertEquals(BotAction::ALLOW, $bot->default_action);
    	}
    }

    public function test_shopping_crawlers_exist_and_allow(): void
    {
    	$shopping = Registry::shopping_crawlers();
    	$this->assertNotEmpty($shopping);

    	// Revenue-critical
    	$this->assertArrayHasKey('google_shopping', $shopping);
    	$this->assertArrayHasKey('facebook_catalog', $shopping);
    	$this->assertArrayHasKey('pinterest_shopping', $shopping);

    	foreach ($shopping as $bot) {
    		$this->assertEquals(BotCategory::SHOPPING_CRAWLER, $bot->category);
    		$this->assertEquals(BotAction::ALLOW, $bot->default_action, "Shopping bot {$bot->id} must ALLOW (revenue)");
    	}
    }

    public function test_cloud_infrastructure_always_allows(): void
    {
    	$cloud = Registry::cloud_infrastructure();
    	$this->assertNotEmpty($cloud);

    	foreach ($cloud as $bot) {
    		$this->assertEquals(BotCategory::CLOUD_INFRASTRUCTURE, $bot->category);
    		$this->assertEquals(BotAction::ALLOW, $bot->default_action, "CRITICAL: Cloud bot {$bot->id} must ALLOW");

    		// Cloud bots should have NO robots_txt_token (they aren't robots-controlled)
    		$this->assertNull($bot->robots_txt_token, "Cloud bot {$bot->id} should not have robots_txt_token");

    		// Cloud bots rely on either static OR dynamic IP ranges.
    		// AWS/Azure ranges are dynamic (service-tag based); CF/Fastly/GCP have static fallbacks.
    		$has_static = !empty($bot->ip_ranges);
    		$is_dynamic_provider = in_array($bot->id, ['aws_elb_health', 'azure_health'], true);

    		$this->assertTrue($has_static || $is_dynamic_provider,
    			"Cloud bot {$bot->id} must have static IP ranges OR be a known dynamic provider");
    	}
    }

    public function test_security_scanners_log_only(): void
    {
    	$scanners = Registry::security_scanners();
    	$this->assertNotEmpty($scanners);

    	foreach ($scanners as $bot) {
    		$this->assertEquals(BotCategory::SECURITY_SCANNER, $bot->category);
    		$this->assertEquals(BotAction::LOG_ONLY, $bot->default_action, "Security scanner {$bot->id} should be LOG_ONLY (auditing)");
    	}
    }

    public function test_bot_category_enum_has_new_values(): void
    {
    	$cases = array_column(BotCategory::cases(), 'value');
    	$this->assertContains('feed_reader', $cases);
    	$this->assertContains('shopping_crawler', $cases);
    	$this->assertContains('cloud_infrastructure', $cases);
    	$this->assertContains('security_scanner', $cases);
    }

    public function test_bot_category_label_method(): void
    {
    	$this->assertEquals('Cloud Infrastructure', BotCategory::CLOUD_INFRASTRUCTURE->label());
    	$this->assertEquals('Shopping Crawler', BotCategory::SHOPPING_CRAWLER->label());
    }

    public function test_bot_category_default_action_hint(): void
    {
    	$this->assertEquals('allow', BotCategory::CLOUD_INFRASTRUCTURE->default_action_hint());
    	$this->assertEquals('allow', BotCategory::SHOPPING_CRAWLER->default_action_hint());
    	$this->assertEquals('allow', BotCategory::FEED_READER->default_action_hint());
    	$this->assertEquals('challenge', BotCategory::AI_CRAWLER->default_action_hint());
    	$this->assertEquals('block', BotCategory::MALICIOUS->default_action_hint());
    	$this->assertEquals('log_only', BotCategory::SECURITY_SCANNER->default_action_hint());
    }

    public function test_all_bots_have_valid_action(): void
    {
    	$valid_actions = array_column(BotAction::cases(), 'value');
    	foreach (Registry::all() as $bot) {
    		$this->assertContains($bot->default_action->value, $valid_actions,
    			"Bot {$bot->id} has invalid action");
    	}
    }

    public function test_all_bots_have_valid_category(): void
    {
    	$valid_categories = array_column(BotCategory::cases(), 'value');
    	foreach (Registry::all() as $bot) {
    		$this->assertContains($bot->category->value, $valid_categories,
    			"Bot {$bot->id} has invalid category {$bot->category->value}");
    	}
    }
}
