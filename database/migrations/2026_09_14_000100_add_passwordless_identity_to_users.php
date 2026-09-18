<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->ulid('public_id')->nullable()->unique();
            $table->string('employee_number', 100)->nullable()->unique();
            $table->string('state', 20)->default('DEACTIVATED')->index();
            $table->string('timezone', 64)->default('UTC');
            $table->dateTime('invited_at', 6)->nullable();
            $table->dateTime('invitation_expires_at', 6)->nullable();
            $table->dateTime('activated_at', 6)->nullable();
            $table->dateTime('last_login_at', 6)->nullable();
            $table->unsignedSmallInteger('failed_auth_attempts')->default(0);
            $table->dateTime('failed_auth_window_started_at', 6)->nullable();
            $table->dateTime('locked_until', 6)->nullable()->index();
            $table->unsignedBigInteger('session_version')->default(1);
            $table->softDeletes('deleted_at', 6);
        });

        DB::table('users')->whereNull('public_id')->orderBy('id')->eachById(
            static function (object $user): void {
                DB::table('users')->where('id', $user->id)->update([
                    'public_id' => (string) Str::ulid(),
                    'email' => mb_strtolower(trim((string) $user->email)),
                    'state' => 'DEACTIVATED',
                    'session_version' => 1,
                ]);
            },
        );

        Schema::table('users', function (Blueprint $table): void {
            $table->ulid('public_id')->nullable(false)->change();
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->dropColumn([
                'public_id', 'employee_number', 'state', 'timezone', 'invited_at',
                'invitation_expires_at', 'activated_at', 'last_login_at',
                'failed_auth_attempts', 'failed_auth_window_started_at', 'locked_until',
                'session_version', 'deleted_at',
            ]);
        });
    }
};
