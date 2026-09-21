<?php

use App\Http\Controllers\Foundation\LivenessController;
use App\Http\Controllers\Foundation\ReadinessController;
use App\Http\Controllers\Foundation\WelcomeController;
use App\Http\Controllers\Identity\ApplicationController;
use App\Http\Controllers\Identity\ApplicationStateController;
use Illuminate\Support\Facades\Route;

Route::get('/', WelcomeController::class)->name('home');

Route::get('/health', LivenessController::class)
    ->withoutMiddleware('web')
    ->name('health');
Route::get('/ready', ReadinessController::class)
    ->withoutMiddleware('web')
    ->name('ready');

Route::middleware('auth')->prefix('admin')->name('admin.')->group(function (): void {
    Route::resource('applications', ApplicationController::class)
        ->only(['index', 'create', 'store', 'edit', 'update']);
    Route::patch('applications/{application}/state', ApplicationStateController::class)
        ->name('applications.state.update');
});
