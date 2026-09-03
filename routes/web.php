<?php

use App\Http\Controllers\Foundation\LivenessController;
use App\Http\Controllers\Foundation\ReadinessController;
use App\Http\Controllers\Foundation\WelcomeController;
use Illuminate\Support\Facades\Route;

Route::get('/', WelcomeController::class)->name('home');

Route::get('/health', LivenessController::class)->name('health');
Route::get('/ready', ReadinessController::class)->name('ready');
