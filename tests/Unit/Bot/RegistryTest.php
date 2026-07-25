<?php

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
        $this->assertNotEmpty($all);

        // Check we have bots from each category
        $categories = array_map(fn($bot) => $bot->category, $all);
        $this->assertContains(BotCategory::SEARCH_ENGINE, $categories);
        $this->assertContains(BotCategory::AI_CRAWLER, $categories);
        $this->assertContains(BotCategory::SOCIAL_CRAWLER, $categories);
        $this->assertContains(BotCategory::SEO_CRAWLER, $categories);
        $this->assertContains(BotCategory::ARCHIVE_CRAWLER, $categories);
        $this->assertContains(BotCategory::MONITORING, $categories);
    }

    public function test_search_engines_have_required_fields(): void
    {
        $engines = Registry::search_engines();

        foreach ($engines as $id => $bot) {
            $this->assertEquals($id, $bot->id);
            $this->assertNotEmpty($bot->name);
            $this->assertNotEmpty($bot->user_agent_patterns);
            $this->assertEquals(BotCategory::SEARCH_ENGINE, $bot->category);
            $this->assertNotNull($bot->robots_txt_token);
            $this->assertEquals(BotAction::ALLOW, $bot->default_action);
        }
    }

    public function test_ai_crawlers_have_challenge_default(): void
    {
        $crawlers = Registry::ai_crawlers();

        foreach ($crawlers as $bot) {
            $this->assertEquals(BotCategory::AI_CRAWLER, $bot->category);
            $this->assertEquals(BotAction::CHALLENGE, $bot->default_action);
            $this->assertNotNull($bot->robots_txt_token);
        }
    }

    public function test_seo_crawlers_have_challenge_default(): void
    {
        $crawlers = Registry::seo_crawlers();

        foreach ($crawlers as $bot) {
            $this->assertEquals(BotCategory::SEO_CRAWLER, $bot->category);
            $this->assertEquals(BotAction::CHALLENGE, $bot->default_action);
        }
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
}
