<?php

use App\Http\Controllers\Foundation\LivenessController;
use App\Http\Controllers\Foundation\ReadinessController;
use App\Http\Controllers\Foundation\WelcomeController;
use App\Http\Controllers\Identity\ApplicationController;
use App\Http\Controllers\Identity\ApplicationStateController;
use App\Http\Controllers\Identity\Authentication\LoginController;
use App\Http\Controllers\Identity\Authentication\OtpChallengeController;
use App\Http\Controllers\Identity\Authentication\PendingAuthenticationCancellationController;
use Illuminate\Support\Facades\Route;

Route::get('/', WelcomeController::class)->name('home');

Route::get('/health', LivenessController::class)
    ->withoutMiddleware('web')
    ->name('health');
Route::get('/ready', ReadinessController::class)
    ->withoutMiddleware('web')
    ->name('ready');

Route::middleware('guest')->group(function (): void {
    Route::get('/login', LoginController::class)->name('login');
    Route::post('/login/otp', [OtpChallengeController::class, 'store'])->name('identity.auth.otp.store');
    Route::get('/login/verify', [OtpChallengeController::class, 'create'])->name('identity.auth.otp.create');
    Route::post('/login/verify', [OtpChallengeController::class, 'update'])->name('identity.auth.otp.verify');
    Route::post('/login/pending/cancel', PendingAuthenticationCancellationController::class)
        ->name('identity.auth.pending.cancel');
});

Route::middleware('auth')->prefix('admin')->name('admin.')->group(function (): void {
    Route::resource('applications', ApplicationController::class)
        ->only(['index', 'create', 'store', 'edit', 'update']);
    Route::patch('applications/{application}/state', ApplicationStateController::class)
        ->name('applications.state.update');
});
