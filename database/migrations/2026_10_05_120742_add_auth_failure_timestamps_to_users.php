<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->json('auth_failure_timestamps')->nullable();
        });

        // Legacy counters cannot recover individual attempt times. Preserve them conservatively
        // for one full window during deployment instead of silently forgiving recent failures.
        $timestamp = now()->format('Y-m-d H:i:s.u');
        DB::table('users')->where('failed_auth_attempts', '>', 0)->orderBy('id')->chunkById(500, function ($users) use ($timestamp): void {
            foreach ($users as $user) {
                DB::table('users')->where('id', $user->id)->update([
                    'auth_failure_timestamps' => json_encode(array_fill(0, (int) $user->failed_auth_attempts, $timestamp), JSON_THROW_ON_ERROR),
                    'failed_auth_window_started_at' => $timestamp,
                ]);
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn('auth_failure_timestamps');
        });
    }
};
