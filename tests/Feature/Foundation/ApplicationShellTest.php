<?php

declare(strict_types=1);

namespace Tests\Feature\Foundation;

use Tests\TestCase;

final class ApplicationShellTest extends TestCase
{
    public function test_foundation_page_renders_the_accessible_enterprise_shell(): void
    {
        $this->withoutVite();

        $this->get('/')
            ->assertOk()
            ->assertSee('Release Governance')
            ->assertSee('Software Release Governance, Testing & Sign-Off')
            ->assertSee('aria-label="Primary navigation"', escape: false)
            ->assertSee('Skip to main content');
    }
}
