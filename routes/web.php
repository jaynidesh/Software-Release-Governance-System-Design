<?php

use App\Http\Controllers\Foundation\LivenessController;
use App\Http\Controllers\Foundation\ReadinessController;
use App\Http\Controllers\Foundation\WelcomeController;
use App\Http\Controllers\Identity\ApplicationController;
use App\Http\Controllers\Identity\ApplicationStateController;
use App\Http\Controllers\Identity\Authentication\LoginController;
use App\Http\Controllers\Identity\Authentication\LogoutController;
use App\Http\Controllers\Identity\Authentication\OtpChallengeController;
use App\Http\Controllers\Identity\Authentication\PendingAuthenticationCancellationController;
use App\Http\Controllers\Identity\Authentication\ReauthenticationController;
use App\Http\Controllers\Identity\InvitationController;
use App\Http\Controllers\Identity\Mfa\PendingMfaController;
use App\Http\Controllers\Identity\Mfa\RecoveryCodeController;
use App\Http\Controllers\Identity\Mfa\TotpEnrollmentController;
use App\Http\Controllers\Identity\RoleAssignmentController;
use App\Http\Controllers\Identity\RoleAssignmentManagementController;
use App\Http\Controllers\Identity\RoleController;
use App\Http\Controllers\Identity\RolePermissionController;
use App\Http\Controllers\Identity\SecurityOverviewController;
use App\Http\Controllers\Identity\SessionController;
use App\Http\Controllers\Identity\UserController;
use App\Http\Controllers\Identity\UserMfaController;
use App\Http\Controllers\Identity\UserSessionController;
use App\Http\Controllers\Identity\UserStateController;
use App\Http\Controllers\Identity\UserUnlockController;
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
    Route::post('/login/resend', [OtpChallengeController::class, 'resend'])->name('identity.auth.otp.resend');
    Route::post('/login/pending/cancel', PendingAuthenticationCancellationController::class)
        ->name('identity.auth.pending.cancel');
    Route::get('/login/mfa', [PendingMfaController::class, 'create'])
        ->middleware('pending.auth:verify')->name('identity.mfa.verify.create');
    Route::post('/login/mfa', [PendingMfaController::class, 'store'])
        ->middleware('pending.auth:verify')->name('identity.mfa.verify.store');
    Route::get('/login/mfa/enroll', [TotpEnrollmentController::class, 'create'])
        ->middleware('pending.auth:enroll')->name('identity.mfa.enroll.create');
    Route::post('/login/mfa/enroll', [TotpEnrollmentController::class, 'store'])
        ->middleware('pending.auth:enroll')->name('identity.mfa.enroll.store');
    Route::get('/login/mfa/recovery-codes', [RecoveryCodeController::class, 'create'])
        ->middleware('pending.auth:recovery')->name('identity.mfa.recovery.create');
    Route::post('/login/mfa/recovery-codes', [RecoveryCodeController::class, 'store'])
        ->middleware('pending.auth:recovery')->name('identity.mfa.recovery.store');
});

Route::middleware('auth')->prefix('admin')->name('admin.')->group(function (): void {
    Route::get('role-assignments', RoleAssignmentManagementController::class)
        ->name('role-assignments.index');
    Route::resource('users', UserController::class)
        ->only(['index', 'create', 'store', 'show', 'edit', 'update'])
        ->middlewareFor(['store', 'update'], 'fresh.reauth:admin.users.index');
    Route::patch('users/{user}/state', UserStateController::class)
        ->middleware('fresh.reauth:admin.users.index')->name('users.state.update');
    Route::post('users/{user}/invitations', [InvitationController::class, 'store'])
        ->middleware('fresh.reauth:admin.users.index')->name('users.invitations.store');
    Route::delete('users/{user}/invitations', [InvitationController::class, 'destroy'])
        ->middleware('fresh.reauth:admin.users.index')->name('users.invitations.destroy');
    Route::post('users/{user}/unlock', [UserUnlockController::class, 'store'])
        ->middleware('fresh.reauth:admin.users.index')->name('users.unlock.store');
    Route::delete('users/{user}/sessions', [UserSessionController::class, 'destroy'])
        ->middleware('fresh.reauth:admin.users.index')->name('users.sessions.destroy');
    Route::delete('users/{user}/mfa', [UserMfaController::class, 'destroy'])
        ->middleware('fresh.reauth:admin.users.index')->name('users.mfa.destroy');
    Route::post('users/{user}/role-assignments', [RoleAssignmentController::class, 'store'])
        ->middleware('fresh.reauth:admin.role-assignments.index')->name('users.role-assignments.store');
    Route::delete(
        'users/{user}/role-assignments/{roleAssignment}',
        [RoleAssignmentController::class, 'destroy'],
    )->scopeBindings()->middleware('fresh.reauth:admin.role-assignments.index')
        ->name('users.role-assignments.destroy');

    Route::resource('roles', RoleController::class)
        ->only(['index', 'create', 'store', 'show', 'edit', 'update'])
        ->middlewareFor(['store', 'update'], 'fresh.reauth:admin.roles.index');
    Route::patch('roles/{role}/state', [RoleController::class, 'changeState'])
        ->middleware('fresh.reauth:admin.roles.index')->name('roles.state.update');
    Route::put('roles/{role}/permissions', [RolePermissionController::class, 'update'])
        ->middleware('fresh.reauth:admin.roles.index')->name('roles.permissions.update');

    Route::resource('applications', ApplicationController::class)
        ->only(['index', 'create', 'store', 'edit', 'update'])
        ->middlewareFor(['store', 'update'], 'fresh.reauth:admin.applications.index');
    Route::patch('applications/{application}/state', ApplicationStateController::class)
        ->middleware('fresh.reauth:admin.applications.index')
        ->name('applications.state.update');
});

Route::middleware('auth')->prefix('security')->name('identity.')->group(function (): void {
    Route::get('/', SecurityOverviewController::class)->name('security.index');
    Route::post('/recovery-codes', [SecurityOverviewController::class, 'regenerateRecoveryCodes'])
        ->middleware(['fresh.reauth', 'no-store.auth'])->name('security.recovery-codes.store');
    Route::post('/totp', [SecurityOverviewController::class, 'rotateTotp'])
        ->middleware(['fresh.reauth', 'no-store.auth'])->name('security.totp.store');
    Route::delete('/sessions', [SessionController::class, 'destroyAll'])->name('sessions.destroy-all');
    Route::delete('/sessions/{authSession}', [SessionController::class, 'destroy'])->name('sessions.destroy');
});

Route::middleware(['no-store.auth', 'auth'])->prefix('reauthenticate')->name('identity.reauthentication.')->group(function (): void {
    Route::get('/', [ReauthenticationController::class, 'show'])->name('show');
    Route::post('/', [ReauthenticationController::class, 'store'])->name('begin');
    Route::post('/verify', [ReauthenticationController::class, 'verify'])->name('verify');
    Route::get('/mfa', [ReauthenticationController::class, 'mfa'])
        ->middleware('pending.auth:verify')->name('mfa.show');
    Route::post('/mfa', [ReauthenticationController::class, 'complete'])
        ->middleware('pending.auth:verify')->name('mfa.complete');
});

Route::post('/logout', LogoutController::class)
    ->middleware(['no-store.auth', 'auth'])
    ->name('logout');
