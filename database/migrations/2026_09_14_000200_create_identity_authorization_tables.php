<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('applications', function (Blueprint $table): void {
            $table->id();
            $table->ulid('public_id')->unique();
            $table->string('code', 100)->unique();
            $table->string('name')->unique();
            $table->boolean('is_active')->default(true)->index();
            $table->timestamps(6);
        });

        Schema::create('roles', function (Blueprint $table): void {
            $table->id();
            $table->ulid('public_id')->unique();
            $table->string('code', 100)->unique();
            $table->string('name')->unique();
            $table->text('description')->nullable();
            $table->boolean('is_system')->default(false);
            $table->boolean('is_active')->default(true)->index();
            $table->timestamps(6);
            $table->softDeletes('deleted_at', 6);
        });

        Schema::create('permissions', function (Blueprint $table): void {
            $table->id();
            $table->string('code', 100)->unique();
            $table->text('description');
            $table->string('scope_type', 20)->index();
        });

        Schema::create('role_permissions', function (Blueprint $table): void {
            $table->foreignId('role_id')->constrained()->cascadeOnDelete();
            $table->foreignId('permission_id')->constrained()->cascadeOnDelete();
            $table->primary(['role_id', 'permission_id']);
        });

        Schema::create('auth_challenges', function (Blueprint $table): void {
            $table->id();
            $table->ulid('public_id')->unique();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('purpose', 30);
            $table->string('code_hmac', 64);
            $table->dateTime('expires_at', 6)->index();
            $table->unsignedSmallInteger('failed_attempts')->default(0);
            $table->dateTime('delivered_at', 6)->nullable();
            $table->dateTime('consumed_at', 6)->nullable();
            $table->dateTime('invalidated_at', 6)->nullable();
            $table->string('request_ip', 45)->nullable();
            $table->string('user_agent', 500)->nullable();
            $table->string('correlation_id', 64)->nullable()->index();
            $table->unsignedTinyInteger('open_slot')->storedAs(
                'CASE WHEN consumed_at IS NULL AND invalidated_at IS NULL THEN 1 ELSE NULL END',
            );
            $table->timestamps(6);
            $table->unique(['user_id', 'purpose', 'open_slot']);
        });

        Schema::create('pending_authentications', function (Blueprint $table): void {
            $table->id();
            $table->ulid('public_id')->unique();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->foreignId('auth_challenge_id')->constrained()->cascadeOnDelete();
            $table->string('purpose', 30);
            $table->string('session_id_hmac', 64);
            $table->unsignedBigInteger('user_session_version');
            $table->dateTime('expires_at', 6)->index();
            $table->dateTime('completed_at', 6)->nullable();
            $table->dateTime('invalidated_at', 6)->nullable();
            $table->string('request_ip', 45)->nullable();
            $table->string('user_agent', 500)->nullable();
            $table->string('correlation_id', 64)->nullable()->index();
            $table->unsignedTinyInteger('active_slot')->storedAs(
                'CASE WHEN completed_at IS NULL AND invalidated_at IS NULL THEN 1 ELSE NULL END',
            );
            $table->timestamps(6);
            $table->unique(['user_id', 'purpose', 'active_slot']);
        });

        Schema::create('user_mfa_methods', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('type', 20);
            $table->text('secret');
            $table->dateTime('confirmed_at', 6)->nullable();
            $table->dateTime('rotated_at', 6)->nullable();
            $table->dateTime('disabled_at', 6)->nullable();
            $table->unsignedBigInteger('last_accepted_timestep')->nullable();
            $table->timestamps(6);
            $table->unique(['user_id', 'type']);
        });

        Schema::create('user_recovery_codes', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_mfa_method_id')->constrained()->cascadeOnDelete();
            $table->string('code_hmac', 64);
            $table->dateTime('used_at', 6)->nullable()->index();
            $table->dateTime('created_at', 6)->useCurrent();
        });

        Schema::create('role_assignments', function (Blueprint $table): void {
            $table->id();
            $table->ulid('public_id')->unique();
            $table->foreignId('user_id')->constrained()->restrictOnDelete();
            $table->foreignId('role_id')->constrained()->restrictOnDelete();
            $table->foreignId('application_id')->nullable()->constrained()->restrictOnDelete();
            $table->dateTime('starts_at', 6);
            $table->dateTime('ends_at', 6)->nullable();
            $table->dateTime('revoked_at', 6)->nullable();
            $table->foreignId('assigned_by')->nullable()->constrained('users')->nullOnDelete();
            $table->foreignId('revoked_by')->nullable()->constrained('users')->nullOnDelete();
            $table->unsignedBigInteger('scope_key')->storedAs('COALESCE(application_id, 0)');
            $table->timestamps(6);
            $table->unique(['user_id', 'role_id', 'scope_key']);
            $table->index(['user_id', 'starts_at', 'ends_at', 'revoked_at']);
        });

        Schema::create('auth_sessions', function (Blueprint $table): void {
            $table->id();
            $table->ulid('public_id')->unique();
            $table->string('session_id')->unique();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->dateTime('started_at', 6);
            $table->dateTime('last_seen_at', 6)->index();
            $table->dateTime('absolute_expires_at', 6)->index();
            $table->dateTime('primary_authenticated_at', 6);
            $table->dateTime('mfa_authenticated_at', 6)->nullable();
            $table->dateTime('reauthenticated_at', 6)->nullable();
            $table->unsignedBigInteger('user_session_version');
            $table->dateTime('revoked_at', 6)->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->string('user_agent', 500)->nullable();
            $table->timestamps(6);
        });

        Schema::create('login_events', function (Blueprint $table): void {
            $table->id();
            $table->ulid('public_id')->unique();
            $table->foreignId('user_id')->nullable()->constrained()->nullOnDelete();
            $table->string('identifier_hmac', 64);
            $table->string('purpose', 30);
            $table->string('result_code', 100)->index();
            $table->string('ip_address', 45)->nullable();
            $table->string('user_agent', 500)->nullable();
            $table->string('correlation_id', 64)->nullable()->index();
            $table->dateTime('occurred_at', 6)->index();
        });

        Schema::create('security_events', function (Blueprint $table): void {
            $table->id();
            $table->ulid('public_id')->unique();
            $table->foreignId('actor_id')->nullable()->constrained('users')->nullOnDelete();
            $table->foreignId('subject_user_id')->nullable()->constrained('users')->nullOnDelete();
            $table->string('event_code', 150)->index();
            $table->unsignedSmallInteger('schema_version');
            $table->json('metadata');
            $table->string('ip_address', 45)->nullable();
            $table->string('user_agent', 500)->nullable();
            $table->string('correlation_id', 64)->nullable()->index();
            $table->dateTime('occurred_at', 6)->index();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_events');
        Schema::dropIfExists('login_events');
        Schema::dropIfExists('auth_sessions');
        Schema::dropIfExists('role_assignments');
        Schema::dropIfExists('user_recovery_codes');
        Schema::dropIfExists('user_mfa_methods');
        Schema::dropIfExists('pending_authentications');
        Schema::dropIfExists('auth_challenges');
        Schema::dropIfExists('role_permissions');
        Schema::dropIfExists('permissions');
        Schema::dropIfExists('roles');
        Schema::dropIfExists('applications');
    }
};
